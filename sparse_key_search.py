#!/usr/bin/env sage -python
"""
Search for the largest logq that still meets a sparse-key security target.

Adapted from the sparse-key estimation code used for
"On the Concrete Hardness Gap Between MLWE and LWE"
(https://eprint.iacr.org/2026/279.pdf).
"""

from __future__ import annotations

import argparse
import math
import sys
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
    format_attack_name,
    format_bits,
    format_detailed_estimate,
    format_estimate,
)


def print_banner() -> None:
    banner_path = Path.cwd() / "ascii.txt"
    if banner_path.is_file():
        banner = banner_path.read_text()
        print(banner, end="" if banner.endswith("\n") else "\n")


def print_run_header(args: argparse.Namespace) -> None:
    print(
        f"[start] logn={args.logn} h={args.h} sigma={args.sigma} "
        f"target_security_bits={args.security_bits} "
        f"search_range=[{args.min_logq}, {args.max_logq}]",
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


def evaluate_candidates(args: argparse.Namespace, logq_values: list[int]):
    results = {}
    candidates = sorted(set(logq_values))
    for logq in candidates:
        print(f"[search] evaluating logq={logq}", flush=True)
        _, estimate = estimate_candidate(args.logn, args.h, args.sigma, logq)
        results[logq] = estimate
        print(
            f"[done] logq={logq} security_bits={format_bits(estimate.best_security_bits)} "
            f"best_attack={format_attack_name(estimate.best_attack)}",
            flush=True,
        )
        if args.verbose:
            print(format_detailed_estimate(estimate), flush=True)
    return results


def meets_security(estimate, security_bits: float) -> bool:
    return estimate.best_security_bits != oo and estimate.best_security_bits >= RR(security_bits)


def find_bounds(args: argparse.Namespace):
    max_results = evaluate_candidates(args, [args.max_logq])
    high = args.max_logq
    high_estimate = max_results[high]
    if meets_security(high_estimate, args.security_bits):
        return (high, high_estimate), None, None

    current_high = high
    while current_high > args.min_logq:
        batch = []
        candidate = current_high
        next_candidate = max(args.min_logq, candidate // 2)
        if next_candidate >= candidate:
            break
        batch.append(next_candidate)

        batch_results = evaluate_candidates(args, batch)
        for logq in sorted(batch, reverse=True):
            estimate = batch_results[logq]
            if meets_security(estimate, args.security_bits):
                return (logq, estimate), (current_high, high_estimate), None
            current_high = logq
            high_estimate = estimate

        if current_high == args.min_logq:
            break

    return None, (current_high, high_estimate), None


def binary_search(args: argparse.Namespace, low_pair, high_pair):
    low, low_estimate = low_pair
    high, high_estimate = high_pair

    while high - low > 1:
        probe = low + math.ceil((high - low) / 2)
        probe_result = evaluate_candidates(args, [probe])[probe]
        if meets_security(probe_result, args.security_bits):
            low = probe
            low_estimate = probe_result
        else:
            high = probe
            high_estimate = probe_result

    return (low, low_estimate), (high, high_estimate)


def main() -> int:
    args = parse_args()
    if args.min_logq < 1:
        raise SystemExit("--min-logq must be at least 1.")
    if args.max_logq < args.min_logq:
        raise SystemExit("--max-logq must be at least --min-logq.")

    print_banner()
    print_run_header(args)

    low_pair, high_pair, _ = find_bounds(args)
    if low_pair is None:
        _, estimate = high_pair
        print()
        print("No admissible logq found in the requested range.")
        print(format_estimate(estimate))
        return 1

    if high_pair is None:
        logq, estimate = low_pair
        print()
        print(
            "Security target is still met at the search limit; "
            "increase --max-logq to continue."
        )
        print(format_estimate(estimate))
        return 0

    best_pair, fail_pair = binary_search(args, low_pair, high_pair)
    best_logq, best_estimate = best_pair
    fail_logq, fail_estimate = fail_pair

    print()
    print(f"result: largest_logq={best_logq}")
    print(f"target security: {args.security_bits} bits")
    print(format_estimate(best_estimate))
    print()
    print(
        f"first failing logq: {fail_logq} "
        f"({format_bits(fail_estimate.best_security_bits)} bits, "
        f"{format_attack_name(fail_estimate.best_attack)})"
    )
    return 0


def _running_as_script() -> bool:
    if __name__ == "__main__":
        return True

    if not sys.argv:
        return False

    return Path(sys.argv[0]).name == "sparse_key_search.py"


if _running_as_script():
    raise SystemExit(main())
