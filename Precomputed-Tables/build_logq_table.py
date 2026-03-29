#!/usr/bin/env python3
"""
Build the logq Markdown tables by running sparse_key_search.py
for each (logn, h, security_bits) cell.

Run from anywhere:
    python3 Precomputed-Tables/build_logq_table.py --sigma 3.2

By default, tables are written to build/output/ inside this script's directory
so they do not overwrite the committed tables.  Pass --output-dir to write
them elsewhere, e.g. --output-dir Precomputed-Tables/ to update in place.

Transient files (cache, logs, per-cell result JSON) are always written to
build/ inside this script's directory and are not tracked by git.  The script
can be safely interrupted and resumed: completed cells are detected from their
result files and skipped; partially-completed cells resume from the estimator
cache written by sparse_key_search.py.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


LOGNS = [12, 13, 14, 15, 16]
HS = [32, 64, 128, 192, 256, 512, 1024]
SECURITY_LEVELS = [128, 192, 256]

SCRIPT_DIR = Path(__file__).resolve().parent

_print_lock = threading.Lock()


def tprint(*args, **kwargs) -> None:
    """Thread-safe print."""
    with _print_lock:
        print(*args, **kwargs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build Markdown logq tables by running sparse_key_search.py."
    )
    parser.add_argument("--sigma", type=float, required=True, help="Error stddev.")
    parser.add_argument(
        "--search-jobs",
        type=int,
        default=max(1, min(4, os.cpu_count() or 1)),
        help="Workers passed to each sparse_key_search call. Default: min(4, CPU count).",
    )
    parser.add_argument(
        "--table-jobs",
        type=int,
        default=1,
        help="Number of (logn, h) pairs to evaluate in parallel. Default: 1.",
    )
    parser.add_argument("--min-logq", type=int, default=20, help="Initial min-logq. Default: 20.")
    parser.add_argument("--max-logq", type=int, default=2000, help="Max logq. Default: 2000.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=SCRIPT_DIR / "build" / "output",
        help=(
            "Directory where the .md tables are written. "
            "Default: build/output/ inside this script's directory."
        ),
    )
    parser.add_argument("--force-recompute", action="store_true", help="Passed to sparse_key_search.")
    return parser.parse_args()


def repo_root() -> Path:
    """Repository root: one level above this script's directory."""
    return Path(__file__).resolve().parent.parent


def sage_command() -> str:
    cmd = shutil.which("sage")
    if cmd is None:
        raise RuntimeError("Could not locate `sage` in PATH.")
    return cmd


def sigma_tag(sigma: float) -> str:
    return f"{sigma:.17g}".replace(".", "_")


def next_min_logq(current: int) -> int:
    if current >= 100:
        return current
    return min(100, max(current + 1, current * 2))


def run_search(
    args: argparse.Namespace, security_bits: int, logn: int, h: int, min_logq: int
) -> tuple[dict, Path]:
    pair_tag = f"logn{logn}_h{h}_sigma{sigma_tag(args.sigma)}"
    build_dir = SCRIPT_DIR / "build"
    cache_file = build_dir / "cache" / f"{pair_tag}.json"
    log_dir = build_dir / "logs" / pair_tag
    log_dir.mkdir(parents=True, exist_ok=True)
    result_file = log_dir / f"security_{security_bits}_min_{min_logq}.result.json"
    log_file = log_dir / f"security_{security_bits}_min_{min_logq}.log"

    if not args.force_recompute and result_file.is_file():
        result = json.loads(result_file.read_text())
        result["log_file"] = str(log_file)
        result["used_min_logq"] = min_logq
        return result, log_file

    cmd = [
        sage_command(),
        "sparse_key_search.py",
        "--",
        "--logn", str(logn),
        "--h", str(h),
        "--sigma", str(args.sigma),
        "--security-bits", str(security_bits),
        "--min-logq", str(min_logq),
        "--max-logq", str(args.max_logq),
        "--jobs", str(args.search_jobs),
        "--cache-file", str(cache_file),
        "--result-file", str(result_file),
        "--color", "never",
    ]
    if args.force_recompute:
        cmd.append("--force-recompute")

    completed = subprocess.run(
        cmd,
        cwd=str(repo_root()),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    log_file.write_text(completed.stdout)

    if completed.returncode != 0 and not result_file.is_file():
        raise RuntimeError(
            f"search failed (exit {completed.returncode})\nlog: {log_file}\ncmd: {' '.join(cmd)}"
        )
    if not result_file.is_file():
        raise RuntimeError(
            f"missing result file\nlog: {log_file}\ncmd: {' '.join(cmd)}"
        )

    result = json.loads(result_file.read_text())
    result["log_file"] = str(log_file)
    result["used_min_logq"] = min_logq
    return result, log_file


def resolve_cell(args: argparse.Namespace, security_bits: int, logn: int, h: int) -> dict:
    min_logq = args.min_logq
    retries = 0

    while True:
        try:
            result, _ = run_search(args, security_bits, logn, h, min_logq)
            result["retry_count"] = retries
            return result
        except Exception as exc:
            if min_logq >= 100:
                raise RuntimeError(
                    f"logn={logn} h={h} security={security_bits} "
                    f"still fails at min_logq={min_logq}\n{exc}"
                ) from exc
            new_min_logq = next_min_logq(min_logq)
            retries += 1
            tprint(
                f"[retry {retries}] logn={logn} h={h} security={security_bits} "
                f"min_logq={min_logq} -> {new_min_logq}",
                flush=True,
            )
            min_logq = new_min_logq


def run_pair(
    args: argparse.Namespace, logn: int, h: int
) -> tuple[tuple[int, int], dict[int, dict]]:
    """
    Run all security levels for one (logn, h) pair sequentially.

    Sequential ordering within a pair is required because all security levels
    share the same per-pair cache file; concurrent writes from separate
    sparse_key_search processes would corrupt it.  Running lower security
    targets first also warms the cache for the higher-security runs that
    follow, since estimates are shared across security levels.
    """
    results: dict[int, dict] = {}
    for security_bits in SECURITY_LEVELS:
        tprint(f"[start] logn={logn} h={h} security={security_bits}", flush=True)
        result = resolve_cell(args, security_bits, logn, h)
        results[security_bits] = result
        tprint(
            f"[done]  logn={logn} h={h} security={security_bits} "
            f"best_logq={result.get('best_logq')} status={result['status']} "
            f"retries={result.get('retry_count', 0)}",
            flush=True,
        )
    return (logn, h), results


def cell_text(result: dict) -> str:
    status = result["status"]
    if status == "ok":
        return str(result["best_logq"])
    if status == "max_reached":
        return f">= {result['best_logq']}"
    if status == "no_admissible":
        return "--"
    return "ERR"


def write_markdown(
    args: argparse.Namespace, security_bits: int, table: dict[tuple[int, int], dict]
) -> Path:
    out = args.output_dir / f"{security_bits}bits_security.md"
    h_headers = " | ".join(str(h) for h in HS)
    h_sep = " | ".join("--:" for _ in HS)
    lines = [
        f"# Ciphertext modulus table for {security_bits} bits of security",
        "",
        f"| logn / h | {h_headers} |",
        f"| -------- | {h_sep} |",
    ]
    for logn in LOGNS:
        row = " | ".join(cell_text(table[(logn, h)]) for h in HS)
        lines.append(f"| {logn} | {row} |")
    out.write_text("\n".join(lines) + "\n")
    return out


def main() -> int:
    args = parse_args()
    if args.search_jobs < 1:
        raise SystemExit("--search-jobs must be at least 1.")
    if args.table_jobs < 1:
        raise SystemExit("--table-jobs must be at least 1.")
    if args.max_logq < args.min_logq:
        raise SystemExit("--max-logq must be at least --min-logq.")

    args.output_dir.mkdir(parents=True, exist_ok=True)

    pairs = [(logn, h) for logn in LOGNS for h in HS]
    total_cells = len(pairs) * len(SECURITY_LEVELS)
    tables: dict[int, dict[tuple[int, int], dict]] = {s: {} for s in SECURITY_LEVELS}

    tprint(
        f"[start] sigma={args.sigma} pairs={len(pairs)} cells={total_cells} "
        f"search_jobs={args.search_jobs} table_jobs={args.table_jobs} "
        f"min_logq={args.min_logq} max_logq={args.max_logq} output_dir={args.output_dir}",
        flush=True,
    )

    errors: list[str] = []

    with ThreadPoolExecutor(max_workers=args.table_jobs) as executor:
        futures = {
            executor.submit(run_pair, args, logn, h): (logn, h)
            for logn, h in pairs
        }
        for future in as_completed(futures):
            logn, h = futures[future]
            try:
                (logn, h), pair_results = future.result()
                for security_bits, result in pair_results.items():
                    tables[security_bits][(logn, h)] = result
            except Exception as exc:
                msg = f"logn={logn} h={h}: {exc}"
                tprint(f"[error] {msg}", flush=True)
                errors.append(msg)
                for security_bits in SECURITY_LEVELS:
                    tables[security_bits][(logn, h)] = {"status": "error", "best_logq": None}

    for security_bits in SECURITY_LEVELS:
        output = write_markdown(args, security_bits, tables[security_bits])
        tprint(f"[write] {output}", flush=True)

    if errors:
        tprint(f"\n[warn] {len(errors)} pair(s) failed:", flush=True)
        for msg in errors:
            tprint(f"  {msg}", flush=True)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
