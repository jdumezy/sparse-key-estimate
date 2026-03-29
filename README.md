# Sparse Key Estimation

Sparse-key security estimation based on the rotated primal-hybrid estimator and the workflow behind the sparse estimates from [On the Concrete Hardness Gap Between MLWE and LWE](https://eprint.iacr.org/2026/279.pdf) by Tabitha Ogilvie.

This repository is a fork adapted to focus only on sparse-key estimation.

If you only need ready-to-read reference values, the [128-bit security table](Precomputed-Tables/128bits_security.md) is the most commonly used.
Tables for [192-bit](Precomputed-Tables/192bits_security.md) and [256-bit](Precomputed-Tables/256bits_security.md) security are also available.
See [Precomputed-Tables/README.md](Precomputed-Tables/README.md) for conventions and how to regenerate the tables.

> **Note:** The values in the tables are estimates based on the rotated primal-hybrid attack from [Ogilvie (2026)](https://eprint.iacr.org/2026/279.pdf), which is the best known attack against sparse-key LWE at the time of writing.
> Security estimates are upper bounds on what this specific attack can achieve.
> A stronger attack or a tighter analysis could lower them.
> They should not be treated as unconditional security guarantees.

## Contents

- `sparse_key_search.py`: CLI for searching the largest `logq` that still meets a target security level.
- `Precomputed-Tables/build_logq_table.py`: script that populates the precomputed tables by running `sparse_key_search.py` over the full `(logn, h, security)` grid.
- `PrimalHybrid/sparse_estimates.py`: reusable sparse-key estimation helpers.
- `PrimalHybrid/lwe_rot_primal.py`: rotated primal-hybrid estimator adapted from the lattice estimator.
- `PrimalHybrid/lattice_estimator/`: upstream lattice-estimator dependency kept as a git submodule.

## Installation

Run the commands below from the repository root.

This project is intended to run inside a Sage environment.
Sage installations are not uniform, so the commands below are written for the packaged Python-based CLI validated on this repository:

- `sage` executable: `/usr/bin/sage`
- Sage Python package: `/usr/lib/python3.14/site-packages/sage`
- Python version: `3.14.3`

If your Sage installation uses the traditional shell wrapper instead, adjust the invocation style accordingly.

1. Clone the repository.
2. Fetch the only required submodule:

```bash
git submodule update --init --recursive PrimalHybrid/lattice_estimator
```

3. Ensure SciPy is installed in the Python environment used by `sage`.

For packaged Sage installs such as the one exposing `/usr/bin/sage`, this is usually:

```bash
python3 -m pip install scipy
```

You can check this with:

```bash
python3 -c "import sage.all; import scipy; print('ok')"
```

## Usage

Search for the largest `logq` meeting a sparse-key security target:

```bash
cd /path/to/sparse-key-estimate
sage sparse_key_search.py -- --logn 13 --h 31 --sigma 3.2
```

The default target is `128` bits. The script prints `ascii.txt` at startup, logs each tested `logq`, and writes computed estimator results to `results_cache.json` so repeated runs can reuse cached points.

The search uses a streaming binary search: it keeps a pool of `--jobs` worker subprocesses running at all times, each evaluating one candidate `logq` value in a separate Sage process. As each worker finishes the interval is tightened and a replacement worker is spawned immediately, so workers are never idle between rounds. Workers whose `logq` is rendered irrelevant by an updated interval are cancelled early.

Example with an explicit security target:

```bash
cd /path/to/sparse-key-estimate
sage sparse_key_search.py -- \
  --logn 13 \
  --h 31 \
  --sigma 3.2 \
  --security-bits 192 \
  --jobs 4
```

Force recomputation and disable terminal colors:

```bash
cd /path/to/sparse-key-estimate
sage sparse_key_search.py -- \
  --logn 13 \
  --h 31 \
  --sigma 3.2 \
  --force-recompute \
  --color never
```

The `--` after the script name is required with this Sage CLI so that the remaining flags are passed to `sparse_key_search.py` instead of being parsed by `sage` itself.

Optional flags:

- `--security-bits`: target security level in bits, default `128`
- `--min-logq`: lower bound for the search interval, default `18`
- `--max-logq`: upper bound for the search interval, default `2000`
- `--cache-file`: path to the JSON cache file, default `results_cache.json`
- `--force-recompute`: ignore cached results and recompute them
- `--jobs`: number of parallel worker subprocesses, default `min(4, CPU count)`
- `--color`: `auto`, `always`, or `never`, default `auto`
- `--verbose`: print per-attack costs for each evaluated point

## Citation

If you use this tool or the precomputed tables in your work, please cite the paper the estimator is based on:

```bibtex
@misc{ogilvie2026hardness,
  author       = {Tabitha Ogilvie},
  title        = {On the Concrete Hardness Gap Between {MLWE} and {LWE}},
  howpublished = {Cryptology ePrint Archive, Paper 2026/279},
  year         = {2026},
  url          = {https://eprint.iacr.org/2026/279}
}
```

If you use the precomputed tables or the sparse-key search tool specifically, you may also cite this repository:

```bibtex
@misc{dumezy2026sparsekey,
  author       = {Jules Dumezy},
  title        = {Sparse Key Estimate},
  howpublished = {\url{https://github.com/jdumezy/sparse-key-estimate}},
  year         = {2026}
}
```

## Notes

- Each candidate `logq` is evaluated in its own Sage subprocess. Evaluation time depends on the parameters and can range from seconds to many minutes.
- The result block is compact and formatted for terminal output. Use `--color never` to disable styling and `--verbose` to print detailed per-attack costs for each point.
- The reported security is the minimum among `primal-without-mitm`, `primal-mitm-square-root`, and `primal-mitm-estimator`.
