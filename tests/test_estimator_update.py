"""Regression tests for attack selection and result reuse, without SageMath."""

import argparse
import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "PrimalHybrid"))

from estimator_version import ESTIMATOR_VERSION, LATTICE_ESTIMATOR_REVISION


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Stand-ins isolate orchestration tests from the mathematical implementation.
# They do not validate the numerical accuracy of the estimator.
sage_all = types.ModuleType("sage.all")
sage_all.RR = float
sage_all.floor = math.floor
sage_all.log = math.log
sage_all.oo = math.inf
estimator = types.ModuleType("lattice_estimator.estimator")
estimator.LWE = estimator.ND = None
estimator.RC = types.SimpleNamespace(MATZOV=object())
rotated = types.ModuleType("lwe_rot_primal")
rotated.rot_primal_hybrid = None

with patch.dict(sys.modules, {
    "sage": types.ModuleType("sage"),
    "sage.all": sage_all,
    "lattice_estimator.estimator": estimator,
    "lwe_rot_primal": rotated,
}):
    estimates = load_module("_unit_estimates", ROOT / "PrimalHybrid/sparse_estimates.py")
    with patch.dict(sys.modules, {"sparse_estimates": estimates}):
        search = load_module("_unit_search", ROOT / "sparse_key_search.py")

tables = load_module("_unit_tables", ROOT / "Precomputed-Tables/build_logq_table.py")


class AttackSelectionTests(unittest.TestCase):
    def test_lowest_cost_wins_for_each_attack(self):
        for winner in range(4):
            with self.subTest(winner=winner):
                costs = [{"rop": 2 ** (64 if i == winner else 128)} for i in range(4)]
                with patch.object(estimates, "build_sparse_lwe_parameters", return_value=types.SimpleNamespace(n=4096)):
                    with patch.object(estimates, "rot_primal_hybrid", side_effect=costs) as attack:
                        result = estimates.estimate_sparse_security(12, 58, 64, 3.2)
                self.assertEqual(result.best_security_bits, 64)
                self.assertEqual(result.best_attack, result.attacks[winner].name)
                configurations = [call.kwargs for call in attack.call_args_list]
                self.assertEqual(
                    [(c["babai"], c["mitm"], c.get("mitm_heuristic")) for c in configurations],
                    [(False, False, None), (True, False, None),
                     (True, True, "square root"), (True, True, "estimator")],
                )
                self.assertTrue(all(c["poly_degree"] == 4096 for c in configurations))

    def test_old_estimates_cannot_be_deserialized(self):
        for data in ({}, {"estimator_version": "old-model"}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                estimates.estimate_from_dict(data)

    def test_versioned_estimate_round_trip(self):
        original = estimates.SparseSecurityEstimate(12, 58, 64, 3.2, 128.0, "test", ())
        payload = estimates.estimate_to_dict(original)
        self.assertEqual(payload["estimator_version"], ESTIMATOR_VERSION)
        self.assertEqual(estimates.estimate_from_dict(payload), original)

    def test_fractional_security_survives_worker_and_cache_round_trips(self):
        for bits in (127.7, math.nextafter(128.0, 0.0), 128.0, 128.7, math.inf):
            with self.subTest(bits=bits):
                attack = estimates.AttackEstimate("test", bits, 1, 2, 3, 4, "")
                original = estimates.SparseSecurityEstimate(13, 214, 2048, 3.2, bits, "test", (attack,))
                restored = original
                for _ in range(2):
                    restored = estimates.estimate_from_dict(json.loads(json.dumps(estimates.estimate_to_dict(restored))))
                self.assertEqual(restored, original)
                self.assertEqual(search.meets_security(restored, 128), bits != math.inf and bits >= 128)
                self.assertEqual(estimates.format_bits(bits), "oo" if bits == math.inf else str(math.floor(bits)))

    def test_legacy_cache_key_is_ignored(self):
        args = argparse.Namespace(logn=12, h=64, sigma=3.2, force_recompute=False)
        old_cache = {"logn=12|h=64|sigma=3.2000000000000002|logq=58": {"old": True}}
        self.assertIsNone(search.load_cached_estimate(args, old_cache, 58, search.TerminalStyle("never")))
        self.assertIn(ESTIMATOR_VERSION, search._cache_key(12, 64, 3.2, 58))

    def test_search_result_records_version(self):
        args = argparse.Namespace(logn=12, h=64, sigma=3.2, security_bits=128, min_logq=20, max_logq=2000)
        self.assertEqual(search.build_search_result(args, "no_admissible")["estimator_version"], ESTIMATOR_VERSION)


class TableResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.script_dir = Path(self.temp.name)
        patcher = patch.object(tables, "SCRIPT_DIR", self.script_dir)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.args = argparse.Namespace(sigma=3.2, force_recompute=False, max_logq=2000, search_jobs=1)
        self.expected = {
            "estimator_version": ESTIMATOR_VERSION,
            "logn": 12, "h": 64, "sigma": 3.2,
            "target_security_bits": 128, "min_logq": 20, "max_logq": 2000,
        }
        self.result = {**self.expected, "status": "ok", "best_logq": 58}
        self.result_file = (
            self.script_dir / "build/logs" / f"logn12_h64_sigma{tables.sigma_tag(3.2)}"
            / "security_128_min_20.result.json"
        )
        self.result_file.parent.mkdir(parents=True)

    def test_matching_completed_result_skips_subprocess(self):
        self.result_file.write_text(json.dumps(self.result))
        with patch.object(tables.subprocess, "run") as run:
            result, _ = tables.run_search(self.args, 128, 12, 64, 20)
        run.assert_not_called()
        self.assertEqual(result["best_logq"], 58)

    def test_changed_version_or_search_inputs_invalidate_results(self):
        for key in self.expected:
            with self.subTest(key=key):
                stale = dict(self.result)
                stale.pop(key)
                self.result_file.write_text(json.dumps(stale))
                self.assertIsNone(tables.read_matching_result(self.result_file, self.expected))
        self.result_file.write_text(json.dumps({**self.result, "max_logq": 1000}))
        self.assertIsNone(tables.read_matching_result(self.result_file, self.expected))

    def test_failed_rerun_cannot_reuse_stale_result(self):
        self.result_file.write_text(json.dumps({**self.result, "estimator_version": "old"}))
        with patch.object(tables, "sage_command", return_value="sage"):
            with patch.object(tables.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "failed")):
                with self.assertRaises(RuntimeError):
                    tables.run_search(self.args, 128, 12, 64, 20)
        self.assertFalse(self.result_file.exists())

    def test_force_recompute_cannot_reuse_previous_result(self):
        self.args.force_recompute = True
        self.result_file.write_text(json.dumps(self.result))
        with patch.object(tables, "sage_command", return_value="sage"):
            with patch.object(tables.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "failed")):
                with self.assertRaises(RuntimeError):
                    tables.run_search(self.args, 128, 12, 64, 20)
        self.assertFalse(self.result_file.exists())

    def test_no_admissible_result_is_valid_with_exit_one(self):
        def run(*args, **kwargs):
            self.result_file.write_text(json.dumps({**self.expected, "status": "no_admissible", "best_logq": None}))
            return subprocess.CompletedProcess([], 1, "No admissible logq.")

        with patch.object(tables, "sage_command", return_value="sage"):
            with patch.object(tables.subprocess, "run", side_effect=run):
                result, _ = tables.run_search(self.args, 128, 12, 64, 20)
        self.assertEqual(result["status"], "no_admissible")


class DependencyTests(unittest.TestCase):
    def test_checked_out_dependency_matches_result_version(self):
        dependency = ROOT / "PrimalHybrid/lattice_estimator"
        if not (dependency / ".git").exists():
            self.skipTest("Dependency submodule is not initialized.")
        revision = subprocess.check_output(["git", "-C", str(dependency), "rev-parse", "HEAD"], text=True).strip()
        self.assertEqual(revision, LATTICE_ESTIMATOR_REVISION)


if __name__ == "__main__":
    unittest.main()
