#!/usr/bin/env sage -python
"""
Search for the largest logq that still meets a sparse-key security target.

Adapted from the sparse-key estimation code used for
"On the Concrete Hardness Gap Between MLWE and LWE"
(https://eprint.iacr.org/2026/279.pdf).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from sage.all import RR, oo

def _candidate_roots():
    roots = [Path.cwd()]

    script_file = globals().get("__file__")
    if script_file:
        roots.append(Path(script_file).resolve().parent)

    argv0 = sys.argv[0] if sys.argv else None
    if argv0 and argv0 not in {"-c", ""}:
        roots.append(Path(argv0).resolve().parent)

    return roots


for root in _candidate_roots():
    primal_hybrid_dir = root / "PrimalHybrid"
    if primal_hybrid_dir.is_dir():
        primal_hybrid_dir_str = str(primal_hybrid_dir)
        if primal_hybrid_dir_str not in sys.path:
            sys.path.insert(0, primal_hybrid_dir_str)
        break
else:
    raise RuntimeError(
        "Could not locate the PrimalHybrid directory. "
        "Run this script from the repository root."
    )

from sparse_estimates import (
    estimate_sparse_security,
    estimate_from_dict,
    estimate_to_dict,
    format_attack_name,
    format_bits,
    format_detailed_estimate,
    format_estimate,
)

DEFAULT_CACHE_PATH = Path("results_cache.json")


class TerminalStyle:
    def __init__(self, mode: str):
        use_color = mode == "always" or (mode == "auto" and sys.stdout.isatty())
        self.enabled = use_color
        self.reset = "\033[0m" if use_color else ""
        self.bold = "\033[1m" if use_color else ""
        self.dim = "\033[2m" if use_color else ""
        self.green = "\033[32m" if use_color else ""
        self.yellow = "\033[33m" if use_color else ""
        self.blue = "\033[34m" if use_color else ""
        self.cyan = "\033[36m" if use_color else ""

    def paint(self, text: str, *styles: str) -> str:
        if not self.enabled:
            return text
        return "".join(styles) + text + self.reset


def _cache_key(logn: int, h: int, sigma: float, logq: int) -> str:
    return f"logn={logn}|h={h}|sigma={sigma:.17g}|logq={logq}"


def _script_path() -> Path:
    argv0 = Path(sys.argv[0])
    if argv0.is_absolute() and argv0.is_file():
        return argv0
    candidate = Path.cwd() / argv0
    if candidate.is_file():
        return candidate.resolve()
    raise RuntimeError("Could not determine the script path for worker subprocesses.")


def _sage_command() -> str:
    sage_cmd = shutil.which("sage")
    if sage_cmd is None:
        raise RuntimeError("Could not locate the `sage` executable in PATH.")
    return sage_cmd


def _worker_command(args: argparse.Namespace, logq: int) -> list[str]:
    return [
        _sage_command(),
        str(_script_path()),
        "--",
        "--worker-logq",
        str(logq),
        "--logn",
        str(args.logn),
        "--h",
        str(args.h),
        "--sigma",
        str(args.sigma),
    ]


def load_cache(cache_path: Path) -> dict:
    if not cache_path.is_file():
        return {}
    data = json.loads(cache_path.read_text())
    return data if isinstance(data, dict) else {}


def save_cache(cache_path: Path, cache: dict) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n")


def save_result(result_path: Path, result: dict) -> None:
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


def build_search_result(
    args: argparse.Namespace,
    status: str,
    best_logq=None,
    best_estimate=None,
    fail_logq=None,
    fail_estimate=None,
) -> dict:
    return {
        "status": status,
        "logn": args.logn,
        "h": args.h,
        "sigma": args.sigma,
        "target_security_bits": args.security_bits,
        "min_logq": args.min_logq,
        "max_logq": args.max_logq,
        "best_logq": best_logq,
        "best_estimate": estimate_to_dict(best_estimate) if best_estimate is not None else None,
        "first_failing_logq": fail_logq,
        "first_failing_estimate": estimate_to_dict(fail_estimate) if fail_estimate is not None else None,
    }


def print_banner() -> None:
    banner_path = Path.cwd() / "ascii.txt"
    if banner_path.is_file():
        banner = banner_path.read_text()
        print(banner, end="" if banner.endswith("\n") else "\n")


def print_run_header(args: argparse.Namespace, style: TerminalStyle) -> None:
    print(
        style.paint("[start] ", style.bold, style.blue)
        + f"logn={args.logn} h={args.h} sigma={args.sigma} "
        f"target_security_bits={args.security_bits} "
        f"search_range=[{args.min_logq}, {args.max_logq}] "
        f"cache={args.cache_file} jobs={args.jobs}",
        flush=True,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Search for the largest integer logq whose sparse-key estimate "
            "still reaches the requested security level."
        )
    )
    parser.add_argument("--logn", type=int, required=True, help="Use n = 2^logn.")
    parser.add_argument("--h", type=int, required=True, help="Sparse secret Hamming weight.")
    parser.add_argument("--sigma", type=float, required=True, help="Error stddev.")
    parser.add_argument(
        "--security-bits",
        type=float,
        default=128.0,
        help="Minimum acceptable security in bits. Default: 128.",
    )
    parser.add_argument(
        "--min-logq",
        type=int,
        default=1,
        help="Smallest logq to consider. Default: 1.",
    )
    parser.add_argument(
        "--max-logq",
        type=int,
        default=4096,
        help="Largest logq to consider before stopping. Default: 4096.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every evaluated point.",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=max(1, min(4, os.cpu_count() or 1)),
        help="Number of parallel worker subprocesses. Default: min(4, CPU count).",
    )
    parser.add_argument(
        "--force-recompute",
        action="store_true",
        help="Ignore cached estimator results and recompute them.",
    )
    parser.add_argument(
        "--cache-file",
        type=Path,
        default=DEFAULT_CACHE_PATH,
        help="Path to the JSON cache file. Default: results_cache.json.",
    )
    parser.add_argument(
        "--result-file",
        type=Path,
        default=None,
        help="Optional JSON file where the final search result is written.",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Color output mode. Default: auto.",
    )
    parser.add_argument(
        "--worker-logq",
        type=int,
        default=None,
        help=argparse.SUPPRESS,
    )
    argv = sys.argv[1:]
    if argv[:1] == ["--"]:
        argv = argv[1:]
    return parser.parse_args(argv)


def estimate_candidate(logn: int, h: int, sigma: float, logq: int):
    estimate = estimate_sparse_security(
        logn=logn,
        logq=logq,
        h=h,
        sigma=sigma,
    )
    return logq, estimate


def load_cached_estimate(args: argparse.Namespace, cache: dict, logq: int, style: TerminalStyle):
    key = _cache_key(args.logn, args.h, args.sigma, logq)
    if args.force_recompute or key not in cache:
        return None
    estimate = estimate_from_dict(cache[key])
    print(
        style.paint("[cache] ", style.dim, style.cyan)
        + f"logq={logq} security_bits={format_bits(estimate.best_security_bits)} "
        f"best_attack={format_attack_name(estimate.best_attack)}",
        flush=True,
    )
    return estimate


def store_estimate(args: argparse.Namespace, cache: dict, logq: int, estimate) -> None:
    key = _cache_key(args.logn, args.h, args.sigma, logq)
    cache[key] = estimate_to_dict(estimate)
    save_cache(args.cache_file, cache)


def launch_worker(args: argparse.Namespace, logq: int, style: TerminalStyle, active_count: int):
    print(
        style.paint("[spawn] ", style.bold, style.yellow)
        + f"logq={logq} active={active_count}/{args.jobs}",
        flush=True,
    )
    return subprocess.Popen(
        _worker_command(args, logq),
        cwd=str(Path.cwd()),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def finalize_worker_result(args: argparse.Namespace, style: TerminalStyle, logq: int, process: subprocess.Popen):
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise RuntimeError(
            f"Worker failed for logq={logq} with exit code {process.returncode}.\n"
            f"stderr:\n{stderr.strip()}\n"
            f"stdout:\n{stdout.strip()}"
        )
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Worker returned invalid JSON for logq={logq}.\noutput:\n{stdout}"
        ) from exc
    estimate = estimate_from_dict(payload)
    print(
        style.paint("[done] ", style.bold, style.green)
        + f"logq={logq} security_bits={format_bits(estimate.best_security_bits)} "
        f"best_attack={format_attack_name(estimate.best_attack)}",
        flush=True,
    )
    if args.verbose:
        print(format_detailed_estimate(estimate), flush=True)
    return estimate


def wait_for_any_worker(pending: dict[int, subprocess.Popen]):
    while True:
        finished = [logq for logq, process in pending.items() if process.poll() is not None]
        if finished:
            return sorted(finished)
        time.sleep(0.1)


def terminate_worker(style: TerminalStyle, logq: int, process: subprocess.Popen):
    process.terminate()
    process.communicate()
    print(
        style.paint("[drop] ", style.dim, style.yellow)
        + f"logq={logq} interval narrowed",
        flush=True,
    )


def choose_gap_probes(low: int, high: int, blocked: set[int], slots: int) -> list[int]:
    points = sorted({low, high, *[probe for probe in blocked if low < probe < high]})
    probes = []
    while len(probes) < slots:
        best_gap = None
        best_probe = None
        for left, right in zip(points, points[1:]):
            if right - left <= 1:
                continue
            probe = left + math.ceil((right - left) / 2)
            if probe in points or probe in probes:
                continue
            gap = right - left
            if best_gap is None or gap > best_gap:
                best_gap = gap
                best_probe = probe
        if best_probe is None:
            break
        probes.append(best_probe)
        points.append(best_probe)
        points.sort()
    return sorted(probes)


def evaluate_uncached_candidates(args: argparse.Namespace, uncached: list[int], style: TerminalStyle):
    results = {}
    if not uncached:
        return results

    if args.jobs <= 1 or len(uncached) == 1:
        for logq in uncached:
            print(
                style.paint("[search] ", style.bold, style.yellow) + f"evaluating logq={logq}",
                flush=True,
            )
            _, estimate = estimate_candidate(args.logn, args.h, args.sigma, logq)
            results[logq] = estimate
            print(
                style.paint("[done] ", style.bold, style.green)
                + f"logq={logq} security_bits={format_bits(estimate.best_security_bits)} "
                f"best_attack={format_attack_name(estimate.best_attack)}",
                flush=True,
            )
            if args.verbose:
                print(format_detailed_estimate(estimate), flush=True)
        return results

    pending = {}
    queue = list(uncached)
    while queue or pending:
        while queue and len(pending) < args.jobs:
            logq = queue.pop(0)
            pending[logq] = launch_worker(args, logq, style, len(pending) + 1)

        for logq in wait_for_any_worker(pending):
            process = pending.pop(logq)
            estimate = finalize_worker_result(args, style, logq, process)
            results[logq] = estimate
    return results


def evaluate_candidates(args: argparse.Namespace, logq_values: list[int], cache: dict, style: TerminalStyle):
    results = {}
    candidates = sorted(set(logq_values))
    uncached = []
    for logq in candidates:
        estimate = load_cached_estimate(args, cache, logq, style)
        if estimate is not None:
            results[logq] = estimate
            continue
        uncached.append(logq)

    uncached_results = evaluate_uncached_candidates(args, uncached, style)
    for logq, estimate in uncached_results.items():
        results[logq] = estimate
        store_estimate(args, cache, logq, estimate)

    return {logq: results[logq] for logq in candidates}


def meets_security(estimate, security_bits: float) -> bool:
    return estimate.best_security_bits != oo and estimate.best_security_bits >= RR(security_bits)


def find_bounds(args: argparse.Namespace, cache: dict, style: TerminalStyle):
    max_results = evaluate_candidates(args, [args.max_logq], cache, style)
    high = args.max_logq
    high_estimate = max_results[high]
    if meets_security(high_estimate, args.security_bits):
        return (high, high_estimate), None, None

    current_high = high
    while current_high > args.min_logq:
        print(
            style.paint("[bounds] ", style.bold, style.blue)
            + f"current interval=[{args.min_logq}, {current_high}]",
            flush=True,
        )
        batch = []
        candidate = current_high
        for _ in range(max(1, args.jobs)):
            next_candidate = max(args.min_logq, candidate // 2)
            if next_candidate >= candidate:
                break
            batch.append(next_candidate)
            if next_candidate == args.min_logq:
                break
            candidate = next_candidate

        if not batch:
            break

        batch_results = evaluate_candidates(args, batch, cache, style)
        for logq in sorted(batch, reverse=True):
            estimate = batch_results[logq]
            if meets_security(estimate, args.security_bits):
                return (logq, estimate), (current_high, high_estimate), None
            current_high = logq
            high_estimate = estimate

        if current_high == args.min_logq:
            break

    return None, (current_high, high_estimate), None


def binary_search(args: argparse.Namespace, low_pair, high_pair, cache: dict, style: TerminalStyle):
    low, low_estimate = low_pair
    high, high_estimate = high_pair
    seen = {low, high}
    pending: dict[int, subprocess.Popen] = {}

    while high - low > 1:
        print(
            style.paint("[refine] ", style.bold, style.blue)
            + f"interval=({low}, {high}) pending={len(pending)}",
            flush=True,
        )
        while len(pending) < args.jobs:
            blocked = seen | set(pending)
            probes = choose_gap_probes(low, high, blocked, args.jobs - len(pending))
            if not probes:
                break
            for probe in probes:
                estimate = load_cached_estimate(args, cache, probe, style)
                if estimate is not None:
                    seen.add(probe)
                    if meets_security(estimate, args.security_bits):
                        if probe > low:
                            low = probe
                            low_estimate = estimate
                    else:
                        if probe < high:
                            high = probe
                            high_estimate = estimate
                    continue
                pending[probe] = launch_worker(args, probe, style, len(pending) + 1)

            stale = [probe for probe in pending if probe <= low or probe >= high]
            for probe in stale:
                process = pending.pop(probe)
                terminate_worker(style, probe, process)

        if high - low <= 1:
            break
        if not pending:
            break

        for probe in wait_for_any_worker(pending):
            process = pending.pop(probe)
            estimate = finalize_worker_result(args, style, probe, process)
            store_estimate(args, cache, probe, estimate)
            seen.add(probe)
            if meets_security(estimate, args.security_bits):
                if probe > low:
                    low = probe
                    low_estimate = estimate
            else:
                if probe < high:
                    high = probe
                    high_estimate = estimate

        stale = [probe for probe in pending if probe <= low or probe >= high]
        for probe in stale:
            process = pending.pop(probe)
            terminate_worker(style, probe, process)

    return (low, low_estimate), (high, high_estimate)


def print_result_block(best_logq: int, best_estimate, fail_logq: int, fail_estimate, args: argparse.Namespace, style: TerminalStyle) -> None:
    print()
    print(style.paint("Result", style.bold))
    print(style.paint(f"  largest logq   {best_logq}", style.bold, style.green))
    print(f"  target bits    {args.security_bits}")
    print(f"  best attack    {format_attack_name(best_estimate.best_attack)}")
    print(f"  security       {format_bits(best_estimate.best_security_bits)} bits")
    print(f"  parameters     logn={best_estimate.logn}, h={best_estimate.h}, sigma={best_estimate.sigma}")
    print()
    print(style.paint("Attack Summary", style.bold))
    for attack in best_estimate.attacks:
        print(
            "  "
            + style.paint(f"{format_attack_name(attack.name):<18}", style.cyan)
            + f"  {format_bits(attack.security_bits):>12} bits"
            + f"  beta={str(attack.beta):>4}"
            + f"  d={str(attack.d):>5}"
            + f"  eta={str(attack.eta):>4}"
            + f"  zeta={str(attack.zeta):>4}"
        )
    print()
    print(style.paint("Boundary", style.bold))
    print(
        f"  first failing logq   {fail_logq} "
        f"({format_bits(fail_estimate.best_security_bits)} bits, "
        f"{format_attack_name(fail_estimate.best_attack)})"
    )


def main() -> int:
    args = parse_args()
    if args.worker_logq is not None:
        estimate = estimate_sparse_security(args.logn, args.worker_logq, args.h, args.sigma)
        sys.stdout.write(json.dumps(estimate_to_dict(estimate)))
        return 0
    if args.min_logq < 1:
        raise SystemExit("--min-logq must be at least 1.")
    if args.max_logq < args.min_logq:
        raise SystemExit("--max-logq must be at least --min-logq.")
    if args.jobs < 1:
        raise SystemExit("--jobs must be at least 1.")

    style = TerminalStyle(args.color)
    cache = load_cache(args.cache_file)

    print_banner()
    print_run_header(args, style)

    low_pair, high_pair, _ = find_bounds(args, cache, style)
    if low_pair is None:
        _, estimate = high_pair
        result = build_search_result(args, status="no_admissible", fail_logq=high_pair[0], fail_estimate=estimate)
        if args.result_file is not None:
            save_result(args.result_file, result)
        print()
        print(style.paint("No admissible logq found in the requested range.", style.bold))
        print(format_estimate(estimate))
        return 1

    if high_pair is None:
        logq, estimate = low_pair
        result = build_search_result(args, status="max_reached", best_logq=logq, best_estimate=estimate)
        if args.result_file is not None:
            save_result(args.result_file, result)
        print()
        print(style.paint("Search limit reached.", style.bold))
        print("Security target is still met at the upper bound.")
        print(f"largest tested logq: {logq}")
        print(format_estimate(estimate))
        return 0

    best_pair, fail_pair = binary_search(args, low_pair, high_pair, cache, style)
    best_logq, best_estimate = best_pair
    fail_logq, fail_estimate = fail_pair
    result = build_search_result(
        args,
        status="ok",
        best_logq=best_logq,
        best_estimate=best_estimate,
        fail_logq=fail_logq,
        fail_estimate=fail_estimate,
    )
    if args.result_file is not None:
        save_result(args.result_file, result)

    print_result_block(best_logq, best_estimate, fail_logq, fail_estimate, args, style)
    return 0


def _running_as_script() -> bool:
    if __name__ == "__main__":
        return True

    if not sys.argv:
        return False

    return Path(sys.argv[0]).name == "sparse_key_search.py"


if _running_as_script():
    raise SystemExit(main())
