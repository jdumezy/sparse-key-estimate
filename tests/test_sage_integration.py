"""Numerical smoke test, enabled when the test interpreter includes SageMath."""

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "PrimalHybrid"))


@unittest.skipUnless(importlib.util.find_spec("sage"), "SageMath is not installed in this interpreter.")
class SageIntegrationTests(unittest.TestCase):
    def test_security_precision_and_conservative_display(self):
        import json
        import math
        from sage.all import RR, oo
        from sparse_estimates import AttackEstimate, SparseSecurityEstimate, estimate_to_dict, estimate_from_dict, format_bits
        from sparse_key_search import meets_security

        for bits in (RR("127.7"), RR(math.nextafter(128.0, 0.0)), RR(128), RR("128.7"), oo):
            with self.subTest(bits=bits):
                attack = AttackEstimate("test", bits, 1, 2, 3, 4, "")
                original = SparseSecurityEstimate(13, 214, 2048, 3.2, bits, "test", (attack,))
                restored = estimate_from_dict(json.loads(json.dumps(estimate_to_dict(original))))
                self.assertEqual(restored, original)
                self.assertEqual(meets_security(restored, 128), bits != oo and bits >= 128)
                self.assertEqual(format_bits(bits), "oo" if bits == oo else str(math.floor(bits)))

    def test_projected_cvp_and_babai_with_updated_dependency(self):
        from sage.all import oo
        from sparse_estimates import estimate_sparse_security, estimate_to_dict, estimate_from_dict

        result = estimate_sparse_security(logn=10, logq=20, h=64, sigma=3.2)
        self.assertEqual(len(result.attacks), 4)
        self.assertTrue(all(attack.security_bits < oo for attack in result.attacks))
        self.assertGreater(result.best_security_bits, 0)
        self.assertEqual(result.best_security_bits, min(attack.security_bits for attack in result.attacks))
        previous_models = [attack for attack in result.attacks if attack.name != "primal-projected-cvp"]
        self.assertLessEqual(result.best_security_bits, min(attack.security_bits for attack in previous_models))
        restored = estimate_from_dict(estimate_to_dict(result))
        self.assertEqual(restored.best_attack, result.best_attack)
        self.assertEqual(restored.best_security_bits, result.best_security_bits)
        self.assertEqual([a.security_bits for a in restored.attacks], [a.security_bits for a in result.attacks])


if __name__ == "__main__":
    unittest.main()
