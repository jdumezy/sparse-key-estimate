# On the Concrete Hardness Gap Between MLWE and LWE

This repository contains code used for:
- rot primal hybrid estimation;
- rot dual hybrid estimation;
- probability simulations.

## Repository structure
- `PrimalHybrid/`
  Estimation code for the primal hybrid attack on MLWE.
  - `lwe_rot_primal.py` RotPrimalHybrid estimator
  - `sparse_estimates.py` used to generate the sparse secret RLWE security estimates from Table 8
  - `lattice_estimator/` we include the lattice estimator as a submodule

- `DualHybrid/`  
  Estimation code for the dual hybrid attack on Kyber MLWE assumptions. This folder is a git submodule based on the original [CodedDualAttack repository](https://github.com/kevin-carrier/CodedDualAttack). All my modifications are contained in `OptimizeCodedDualAttack/`.
  In `OptimizeCodedDualAttack/`, the relevant files for RotDualHybrid are:
  - `rot_optimizer_naive.py`
  - `rot_utilitaries.py`
  - `rotated_*.pkl` (initial/intermediate/final results files corresponding to the original `.pkl` files)
  - `ring_results_full.txt` (final results used in the paper)
  - `read_final_results.py` (parses the final results `.pkl` file)

- `simulations/`
  Probability simulations used in the paper.
  - `simulations/primal/simulate_probabilities.py`
  - `simulations/dual/simulate_probabilities.py`


## Setup
After cloning this repository, run
```bash
git submodule update --init --recursive
```
to clone the required submodules.

# Primal Hybrid
After cloning and activating sage, you can run
```bash
cd PrimalHybrid
python3 sparse_estimates.py
```
to generate estimates for the sparse parameter sets in that file.

# Dual Hybrid
After cloning and activating sage, you can run
```bash
cd DualHybrid/OptimizeCodedDualAttack
make
python3 rot_optimizer_naive.py
```
This will take several hours to complete.

