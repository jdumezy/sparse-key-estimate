"""
Sparse-key security estimation helpers.

Adapted from the original sparse-estimation workflow used for
"On the Concrete Hardness Gap Between MLWE and LWE"
(https://eprint.iacr.org/2026/279.pdf).
"""

from dataclasses import dataclass

from sage.all import RR, log, oo

from lattice_estimator.estimator import LWE, ND, RC

from lwe_rot_primal import rot_primal_hybrid


@dataclass(frozen=True)
class AttackEstimate:
    name: str
    cost: object
    security_bits: object


@dataclass(frozen=True)
class SparseSecurityEstimate:
    logn: int
    logq: int
    h: int
    sigma: float
    best_security_bits: object
    best_attack: str
    attacks: tuple[AttackEstimate, ...]


def build_sparse_lwe_parameters(logn: int, logq: int, h: int, sigma: float):
    n = 2 ** logn
    h_pos = h // 2
    h_neg = h - h_pos
    return LWE.Parameters(
        n=n,
        q=2 ** logq,
        Xs=ND.SparseTernary(p=h_pos, m=h_neg, n=n),
        Xe=ND.DiscreteGaussian(stddev=sigma),
    )


def _security_bits(cost):
    rop = cost["rop"]
    if rop == oo:
        return oo
    return log(RR(rop), 2)


def format_bits(value) -> str:
    if value == oo:
        return "oo"
    return str(RR(value).n(12))


def format_attack_name(name: str) -> str:
    return name.replace("primal-", "").replace("-", " ")


def format_attack_summary(attack: AttackEstimate) -> str:
    cost = attack.cost
    beta = cost.get("beta", "?")
    d = cost.get("d", "?")
    eta = cost.get("eta", "?")
    zeta = cost.get("zeta", cost.get("ζ", "?"))
    return (
        f"{format_attack_name(attack.name)}: "
        f"{format_bits(attack.security_bits)} bits, "
        f"beta={beta}, d={d}, eta={eta}, zeta={zeta}"
    )


def estimate_sparse_security(
    logn: int,
    logq: int,
    h: int,
    sigma: float,
    cost_model=RC.MATZOV,
) -> SparseSecurityEstimate:
    params = build_sparse_lwe_parameters(logn, logq, h, sigma)
    poly_degree = params.n

    attack_costs = (
        ("primal-without-mitm", rot_primal_hybrid(
            params,
            babai=True,
            mitm=False,
            poly_degree=poly_degree,
            red_cost_model=cost_model,
        )),
        ("primal-mitm-square-root", rot_primal_hybrid(
            params,
            babai=True,
            mitm=True,
            poly_degree=poly_degree,
            mitm_heuristic="square root",
            red_cost_model=cost_model,
        )),
        ("primal-mitm-estimator", rot_primal_hybrid(
            params,
            babai=True,
            mitm=True,
            poly_degree=poly_degree,
            mitm_heuristic="estimator",
            red_cost_model=cost_model,
        )),
    )

    attacks = tuple(
        AttackEstimate(
            name=name,
            cost=cost,
            security_bits=_security_bits(cost),
        )
        for name, cost in attack_costs
    )
    best = min(attacks, key=lambda attack: attack.security_bits)

    return SparseSecurityEstimate(
        logn=logn,
        logq=logq,
        h=h,
        sigma=sigma,
        best_security_bits=best.security_bits,
        best_attack=best.name,
        attacks=attacks,
    )


def format_estimate(estimate: SparseSecurityEstimate) -> str:
    lines = [
        f"parameters: logn={estimate.logn}, logq={estimate.logq}, h={estimate.h}, sigma={estimate.sigma}",
        f"best attack: {format_attack_name(estimate.best_attack)}",
        f"security: {format_bits(estimate.best_security_bits)} bits",
    ]
    for attack in estimate.attacks:
        lines.append(f"  - {format_attack_summary(attack)}")
    return "\n".join(lines)


def format_detailed_estimate(estimate: SparseSecurityEstimate) -> str:
    lines = [format_estimate(estimate)]
    for attack in estimate.attacks:
        lines.append("")
        lines.append(f"{format_attack_name(attack.name)}:")
        lines.append(str(attack.cost))
    return "\n".join(lines)
