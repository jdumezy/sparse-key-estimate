"""Shared result identity, importable without SageMath."""

# Bump the model version whenever attack selection or costing changes.
# Keep the dependency revision in sync with the lattice_estimator submodule.
LATTICE_ESTIMATOR_REVISION = "6019056011d10d7e9c30a0d5da2d2f729fbc2eec"
ESTIMATOR_VERSION = f"rot-primal-projected-cvp-v1+{LATTICE_ESTIMATOR_REVISION}"
