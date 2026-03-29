# Precomputed tables for sparse keys

This directory contains precomputed Markdown tables for sparse-key parameter sets.
Each table gives the largest `logq` found for a fixed target security level.

## Common conventions

All tables in this directory use:

- error standard deviation `sigma = 3.2`
- power-of-two ring dimension `n = 2^logn`
- sparse ternary secret with Hamming weight `h`
- ciphertext modulus `q = 2^logq`

## Files

- [`128bits_security.md`](128bits_security.md)
  Largest `logq` values targeting at least `128` bits of security.
- [`192bits_security.md`](192bits_security.md)
  Largest `logq` values targeting at least `192` bits of security.
- [`256bits_security.md`](256bits_security.md)
  Largest `logq` values targeting at least `256` bits of security.

## Table layout

Each table is organized as follows:

- rows: `logn`
- columns: secret Hamming weight `h`
- cell value: the largest admissible `logq`

For example, a cell containing `19` means that the search found `q = 2^19` as the largest modulus meeting the target security level for that `(logn, h)` pair.

## Special cell values

- an integer such as `19`
  A concrete `logq` value was found.
- `--`
  No admissible `logq` was found in the searched range for that cell.
- an empty cell
  The entry has not been filled yet.

## Regenerating the tables

`build_logq_table.py` in this directory computes all cells and writes the three table files.
It requires SageMath and the repository setup described in the top-level README.

```bash
# From the repository root
python3 Precomputed-Tables/build_logq_table.py --sigma 3.2
```

By default, tables are written to `build/output/` inside the `Precomputed-Tables/` directory so they do not overwrite the committed tables.
To update the committed tables in place, pass `--output-dir Precomputed-Tables/`.

The script can be interrupted and resumed safely: completed cells are detected from their result files and skipped on the next run; partially-completed cells resume from the estimator cache.

Optional flags:

- `--search-jobs N`: worker subprocesses per `(logn, h)` cell (default: `min(4, CPU count)`)
- `--table-jobs N`: number of `(logn, h)` pairs evaluated in parallel (default: `1`)
- `--min-logq`: lower bound of the search range (default: `20`)
- `--max-logq`: upper bound of the search range (default: `2000`)
- `--output-dir`: where to write the `.md` table files (default: `build/output/` inside this directory)
- `--force-recompute`: ignore cached results and recompute from scratch

Transient files (per-cell logs, result JSON, estimator cache) are always written to `build/` inside this directory and are not tracked by git.

## Parallelization

The script has two levels of parallelism:

- **`--table-jobs`**: independent `(logn, h)` pairs run concurrently.
- **`--search-jobs`**: worker subprocesses used by the binary search within each cell.

The binary search for one cell converges in O(log₂(range)) evaluations — roughly 11 for the default range.
Beyond 4–8 workers per cell, additional `search_jobs` yield diminishing returns because most would be cancelled before finishing as the interval narrows.
Spreading cores across more cells with `table_jobs` is more effective.

Recommended split for a machine with `C` available cores:

```
--table-jobs N --search-jobs M   where N × M ≈ C, M between 3 and 8
```

For example, on a 96-core machine: `--table-jobs 24 --search-jobs 4`.

> **Runtime note:** The full table (all logn, h, and security-level combinations at sigma=3.2) took roughly 2 days of wall-clock time on a dual-socket server with two Intel Xeon Platinum 8268 (96 threads total) using `--table-jobs 24 --search-jobs 4`.
> Peak RAM usage stayed well below 64 GB despite the server having 192 GB available.
