# Sparse Key Estimation

Sparse-key security estimation based on the rotated primal-hybrid estimator and the workflow behind the sparse estimates from [On the Concrete Hardness Gap Between MLWE and LWE](https://eprint.iacr.org/2026/279.pdf) by Tabitha Ogilvie.

This repository is a fork adapted to focus only on sparse-key estimation.

## Contents

- `PrimalHybrid/lwe_rot_primal.py`: rotated primal-hybrid estimator adapted from the lattice estimator.
- `PrimalHybrid/sparse_estimates.py`: reusable sparse-key estimation helpers.
- `sparse_key_search.py`: CLI for searching the largest `logq` that still meets a target security level.
- `PrimalHybrid/lattice_estimator/`: upstream lattice-estimator dependency kept as a git submodule.

## Installation

Run the commands below from the repository root.

This project is intended to run inside a Sage environment. Sage installations are not uniform, so the commands below are written for the packaged Python-based CLI validated on this repository:

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

The default target is `128` bits. The script logs each tested `logq` so the run visibly progresses even when an estimate is slow.

Example with an explicit security target:

```bash
cd /path/to/sparse-key-estimate
sage sparse_key_search.py -- \
  --logn 13 \
  --h 31 \
  --sigma 3.2 \
  --security-bits 192
```

The `--` after the script name is required with this Sage CLI so that the remaining flags are passed to `sparse_key_search.py` instead of being parsed by `sage` itself.

Optional flags:

- `--security-bits`: target security level in bits, default `128`
- `--min-logq`: lower bound for the search interval, default `1`
- `--max-logq`: upper bound for the search interval, default `4096`
- `--verbose`: print every candidate tested

## Notes

- Each candidate `logq` can take time to evaluate. The search is currently serial.
- The reported security is the minimum among `primal-without-mitm`, `primal-mitm-square-root`, and `primal-mitm-estimator`.
