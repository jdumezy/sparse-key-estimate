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
    security_bits: object
    beta: object
    d: object
    eta: object
    zeta: object
    cost_text: str


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
    return (
        f"{format_attack_name(attack.name)}: "
        f"{format_bits(attack.security_bits)} bits, "
        f"beta={attack.beta}, d={attack.d}, eta={attack.eta}, zeta={attack.zeta}"
    )


def _json_value(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def attack_to_dict(attack: AttackEstimate) -> dict:
    return {
        "name": attack.name,
        "security_bits": format_bits(attack.security_bits),
        "beta": _json_value(attack.beta),
        "d": _json_value(attack.d),
        "eta": _json_value(attack.eta),
        "zeta": _json_value(attack.zeta),
        "cost_text": attack.cost_text,
    }


def _parse_bits(value: str):
    if value == "oo":
        return oo
    return RR(value)


def attack_from_dict(data: dict) -> AttackEstimate:
    return AttackEstimate(
        name=data["name"],
        security_bits=_parse_bits(data["security_bits"]),
        beta=data.get("beta", "?"),
        d=data.get("d", "?"),
        eta=data.get("eta", "?"),
        zeta=data.get("zeta", "?"),
        cost_text=data.get("cost_text", ""),
    )


def estimate_to_dict(estimate: SparseSecurityEstimate) -> dict:
    return {
        "logn": estimate.logn,
        "logq": estimate.logq,
        "h": estimate.h,
        "sigma": estimate.sigma,
        "best_security_bits": format_bits(estimate.best_security_bits),
        "best_attack": estimate.best_attack,
        "attacks": [attack_to_dict(attack) for attack in estimate.attacks],
    }


def estimate_from_dict(data: dict) -> SparseSecurityEstimate:
    return SparseSecurityEstimate(
        logn=data["logn"],
        logq=data["logq"],
        h=data["h"],
        sigma=data["sigma"],
        best_security_bits=_parse_bits(data["best_security_bits"]),
        best_attack=data["best_attack"],
        attacks=tuple(attack_from_dict(attack) for attack in data["attacks"]),
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
            security_bits=_security_bits(cost),
            beta=cost.get("beta", "?"),
            d=cost.get("d", "?"),
            eta=cost.get("eta", "?"),
            zeta=cost.get("zeta", cost.get("ζ", "?")),
            cost_text=str(cost),
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
        lines.append(attack.cost_text)
    return "\n".join(lines)
