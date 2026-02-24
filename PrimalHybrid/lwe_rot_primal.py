# this code is adapted from the lattice estimator, https://github.com/malb/lattice-estimator

# in particular, we use the class `RotPrimalHybrid` which corresponds to the class `PrimalHybrid`

# everywhere we have made an edit to this class, we make use the flag #EDIT

from functools import partial

from sage.all import oo, ceil, sqrt, log, RR, ZZ, cached_function
from lattice_estimator.estimator.reduction import delta as deltaf
from lattice_estimator.estimator.reduction import cost as costf
from lattice_estimator.estimator.util import local_minimum
from lattice_estimator.estimator.cost import Cost
from lattice_estimator.estimator.lwe_parameters import LWEParameters
from lattice_estimator.estimator.simulator import normalize as simulator_normalize
from lattice_estimator.estimator.prob import guessing_set_and_hit_probability
from lattice_estimator.estimator.prob import amplify as prob_amplify
from lattice_estimator.estimator.prob import babai as prob_babai
from lattice_estimator.estimator.prob import mitm_babai_probability
from lattice_estimator.estimator.io import Logging
from lattice_estimator.estimator.conf import red_cost_model as red_cost_model_default
from lattice_estimator.estimator.conf import red_shape_model as red_shape_model_default
from lattice_estimator.estimator.conf import max_beta as max_beta_global
from scipy.optimize import minimize_scalar

import sys

from lattice_estimator.estimator.lwe_primal import PrimalUSVP, PrimalHybrid, primal_usvp

# EDIT: new function to account for rotations in power of two cyclotomics
def rot_guessing_set_and_hit_probability(zeta, Xs, hw, poly_degree):
    """
    Return the size of the guessing set and the probability of hitting the secret for a given guessing dimension ζ and Hamming weight hw when using rotations in the module over ZZ[X]/(X^poly_degree + 1).

    The guessing set is formed of all zeta length strings of weight at most hw, and all rotations.

    """
    search_space, hit_probability = guessing_set_and_hit_probability(zeta, Xs, hw)
    
    rot_search_space = search_space * poly_degree
    rot_hit_probability = 1 - (1 - hit_probability) ** poly_degree
    
    return rot_search_space, rot_hit_probability
    
class RotPrimalHybrid:
    @classmethod
    def babai_cost(cls, d):
        return Cost(rop=max(d, 1) ** 2)

    @classmethod
    def svp_dimension(cls, r, D, is_homogeneous=False):
        """
        Return required svp dimension for a given lattice shape and distance.

        :param r: squared Gram-Schmidt norms

        """
        from math import lgamma, log, pi

        def ball_log_vol(n):
            return (n / 2.0) * log(pi) - lgamma(n / 2.0 + 1)

        # If B is a basis with GSO profiles r, this returns an estimate for the shortest vector in the lattice
        # [ B | * ]
        # [ 0 |tau]
        # if the tau is None, the instance is homogeneous, and we omit the final row/column.
        def svp_gaussian_heuristic_log_input(r, tau):
            if tau is None:
                n = len(list(r))
                log_vol = sum(r)
            else:
                n = len(list(r)) + 1
                log_vol = sum(r) + 2 * log(tau)
            log_gh = 1.0 / n * (log_vol - 2 * ball_log_vol(n))
            return log_gh

        d = len(r)
        r = [log(x) for x in r]

        if d > 4096:
            # chosen since RC.ADPS16(1754, 1754).log(2.) = 512.168000000000
            min_i = d - 1754
        else:
            min_i = 0

        if is_homogeneous:
            tau = None
            for i in range(min_i, d):
                if svp_gaussian_heuristic_log_input(r[i:], tau) < log(D.stddev**2 * (d - i)):
                    return ZZ(d - (i - 1))
            return ZZ(2)

        else:
            # we look for the largest i such that (pi_i(e), tau) is shortest in the embedding lattice
            # [pi_i(B) | * ]
            # [   0    |tau]
            tau = D.stddev
            for i in range(min_i, d):
                if svp_gaussian_heuristic_log_input(r[i:], tau) < log(D.stddev**2 * (d - i) + tau ** 2):
                    return ZZ(d - (i - 1) + 1)
            return ZZ(2)

    @classmethod
    def svp_dimension_gsa(cls, d, log_total_vol, log_delta, D, is_homogeneous=False):
        """
        Return required svp dimension assuming the GSA on a lattice with a given volume and rank.

        """
        from math import lgamma, log, pi

        def log_projected_vol(i):
            return (d - i) / d * log_total_vol - i * (d - i) * log_delta

        def ball_log_vol(n):
            return (n / 2.0) * log(pi) - lgamma(n / 2.0 + 1)

        # If B is a BKZ reduced basis, this returns an estimate for the shortest vector in the lattice
        # [ B | * ]
        # [ 0 |tau]
        # under the GSA assumption, where total_vol is the volume of B, and delta is the root Hermite factor.
        # if the tau is None, the instance is homogeneous, and we omit the final row/column.
        def svp_gaussian_heuristic_gsa(i, tau):
            if tau is None:
                n = d - i
                log_vol = 2 * log_projected_vol(i)
            else:
                n = d - i + 1
                log_vol = 2 * log_projected_vol(i) + 2 * log(tau)
            log_gh = 1.0 / n * (log_vol - 2 * ball_log_vol(n))
            return log_gh

        if d > 4096:
            # chosen since RC.ADPS16(1754, 1754).log(2.) = 512.168000000000
            min_i = d - 1754
        else:
            min_i = 0

        if is_homogeneous:
            tau = None
            for i in range(min_i, d):
                if svp_gaussian_heuristic_gsa(i, tau) < log(D.stddev**2 * (d - i)):
                    return ZZ(d - (i - 1))
            return ZZ(2)
        else:
            # we look for the largest i such that (pi_i(e), tau) is shortest in the embedding lattice
            # [pi_i(B) | * ]
            # [   0    |tau]
            tau = D.stddev
            for i in range(min_i, d):
                if svp_gaussian_heuristic_gsa(i, tau) < log(D.stddev**2 * (d - i) + tau ** 2):
                    return ZZ(d - (i - 1) + 1)
            return ZZ(2)

    @classmethod
    @cached_function
    def beta_params(
        cls,
        beta: int,
        params: LWEParameters,
        zeta: int = 0,
        babai=False,
        mitm=False,
        m: int = oo,
        d: int = None,
        red_shape_model=red_shape_model_default,
        red_cost_model=red_cost_model_default,
        log_level=5,
    ):
        '''
        The costs in a Primal Hybrid attack when we run BKZ-β on the lattice basis.

        :param beta: blocksize.
        :param params: LWE parameters.
        :param zeta: guessing dimension.
        :param babai: Insist on Babai's algorithm for finding close vectors.
        :param mitm: Simulate MITM approach (√ of search space).
        :param m: number of LWE samples.
        :param d: rank of lattice to BKZ reduce. If None, we calculate the optimal dimension.

        We return a dictionary of the following values:

        - bkz_cost: the cost of BKZ-β according to the cost model
        - d: the lattice rank.
        - svp_cost: the cost of the CVP call when we use this β, according to babai=True/False.
        - eta: the projection dimension.
        - babai_probability: the probability the Babai lift in the CVP subroutine succeeds.
        - mitm_probability: the probability a mitm speedup succeeds. If mitm=False, returns 1.
        '''
        if m - zeta < beta:
            # cannot BKZ-β on a basis of dimension < β
            return {"bkz_cost": Cost(rop=oo)}

        if d is not None and d < beta:
            # cannot BKZ-β on a basis of dimension < β
            return {"bkz_cost": Cost(rop=oo)}

        simulator = simulator_normalize(red_shape_model)
        xi = PrimalUSVP._xi_factor(params.Xs, params.Xe)

        if d is None:
            delta = deltaf(beta)
            d = max(beta, min(ceil(sqrt((params.n - zeta) * log(params.q / xi) / log(delta))), m - zeta))

        # 1. Simulate BKZ-β
        # We simulate BKZ-β on the dxd basis B_BKZ:
        # [q I_m |  A_{n - zeta}  ]
        # [  0   | xi I_{n - zeta}]
        # r holds the simulated squared GSO norms after BKZ-β
        r = simulator(d, params.n - zeta, params.q, beta, xi=xi, tau=False, dual=True)
        bkz_cost = costf(red_cost_model, beta, d)

        # 2. Required SVP dimension η + 1
        # We select η such that (pi_{d - η + 1}(e | s_{n - zeta}), tau) is the shortest vector in
        # [pi(B_BKZ) | t ]
        # [    0     |tau]
        if babai:
            eta = 2
            svp_cost = PrimalHybrid.babai_cost(d)
        else:
            # we scaled the lattice so that χ_e is what we want
            if red_shape_model == "gsa":
                log_vol = RR((d - (params.n - zeta)) * log(params.q) + (params.n - zeta) * log(xi))
                log_delta = RR(log(deltaf(beta)))
                svp_dim = PrimalHybrid.svp_dimension_gsa(d, log_vol, log_delta, params.Xe, params._homogeneous)
            else:
                svp_dim = PrimalHybrid.svp_dimension(r, params.Xe, is_homogeneous=params._homogeneous)
            eta = svp_dim if params._homogeneous else svp_dim - 1
            if eta > d:
                # Lattice reduction was not strong enough to "reveal" the LWE solution.
                # A larger `beta` should perhaps be attempted.
                return {"svp_cost": Cost(rop=oo)}
            # we make one svp call on a lattice of rank eta + 1
            svp_cost = costf(red_cost_model, svp_dim, svp_dim)
            # when η ≪ β, lifting may be a bigger cost
            svp_cost["rop"] += PrimalHybrid.babai_cost(d - eta)["rop"]

        if babai:
            babai_probability = prob_babai(r, sqrt(d) * params.Xe.stddev)
        else:
            babai_probability = prob_babai(r[:d-eta], sqrt(d - eta) * params.Xe.stddev)

        if mitm and zeta > 0:
            if babai:
                mitm_probability = mitm_babai_probability(r, params.Xe.stddev)
            else:
                # TODO: the probability in this case needs to be analysed
                mitm_probability = 1
        else:
            mitm_probability = 1

        return {"bkz_cost": bkz_cost,
                "d": d,
                "svp_cost": svp_cost,
                "eta": eta,
                "babai_probability": babai_probability,
                "mitm_probability": mitm_probability}

    @staticmethod
    @cached_function
    def cost(
        beta: int,
        params: LWEParameters,
        zeta: int = 0,
        babai=False,
        mitm=False,
        m: int = oo,
        d: int = None,
        red_shape_model=red_shape_model_default,
        red_cost_model=red_cost_model_default,
        search_space=None,
        hit_probability=None,
        poly_degree=None, # EDIT: we pass the polynomial degree for using rotations. If None, assume RLWE and poly_degree = n.
        mitm_heuristic="square root", # EDIT: we allow choosing between different heuristics for the speed up achieved by MITM
        log_level=5,
    ):
        """
        Cost of the hybrid attack.

        :param beta: Block size.
        :param params: LWE parameters.
        :param zeta: Guessing dimension ζ ≥ 0.
        :param babai: Insist on Babai's algorithm for finding close vectors.
        :param mitm: Simulate MITM approach (√ of search space).
        :param m: We accept the number of samples to consider from the calling function.
        :param d: We optionally accept the dimension to pick.
        :param search_space: the size of the search space in a primal hybrid attack.
        :param hit_probability: the probability this search space hits the secret.
        :param poly_degree: the polynomial degree for using rotations in power of two cyclotomics. If None, assume RLWE and poly_degree = n.
        :param mitm_heuristic: the heuristic to use for the speed up achieved by MITM. If `square root`, we assume a √ of the search space speed up. If `estimator`, we assume a √(poly_degree) * √(search_space) speed up. If mitm=False, this parameter is ignored.

        .. note :: This is the lowest level function that runs no optimization, it merely reports
           costs.

        """
        beta_params = PrimalHybrid.beta_params(beta=beta,
                                               params=params,
                                               zeta=zeta,
                                               babai=babai,
                                               mitm=mitm, m=m,
                                               d=d,
                                               red_shape_model=red_shape_model,
                                               red_cost_model=red_cost_model)
        if len(beta_params.keys()) == 1:
            # this beta is not sufficient to reveal the error for these params,
            # either due to insufficient samples or projection dim > d.
            return Cost(rop=oo)
        
        if poly_degree is None:
            # assume this is RLWE, so poly_degree = n
            poly_degree = params.n

        # Search
        # MITM or no MITM
        def ssf(search_space):
            if not mitm:
                return search_space
            if mitm and mitm_heuristic == "square root":
                return RR(sqrt(search_space))
            if mitm and mitm_heuristic == "estimator":
                return RR(sqrt(poly_degree) * sqrt(search_space))
            else:
                raise ValueError(f"unrecognised mitm heuristic: {mitm=}, {mitm_heuristic=}, expected heuristic one of `estimator`, `square root`.")

        # if no search_space provided, we determine the optimal one recursively
        if search_space is None or hit_probability is None:
            f = partial(
                PrimalHybrid.cost,
                beta=beta,
                params=params,
                zeta=zeta,
                babai=babai,
                mitm=mitm,
                m=m,
                d=beta_params["d"],
                red_shape_model=red_shape_model,
                red_cost_model=red_cost_model,
            )
            min_hw = max(0, zeta - params.n + params.Xs.hamming_weight)
            max_hw = min(params.Xs.hamming_weight, zeta)
            cost = Cost(rop=oo)
            for hw in range(min_hw, max_hw + 1):
                # EDIT: we use the new function to account for rotations in power of two cyclotomics
                search_space, hit_probability = rot_guessing_set_and_hit_probability(zeta, params.Xs, hw, poly_degree)
                new_cost = f(search_space=search_space, hit_probability=hit_probability)
                if new_cost["rop"] > cost["rop"]:
                    # cost has started increasing, time to stop
                    return cost
                cost = new_cost
            return cost

        else:
            # we have the search_space and hit probability
            svp_cost = beta_params["svp_cost"].repeat(ssf(search_space))
            probability = hit_probability

        probability *= beta_params["babai_probability"]
        probability *= beta_params["mitm_probability"]

        bkz_cost = beta_params["bkz_cost"]
        ret = Cost()
        ret["rop"] = bkz_cost["rop"] + svp_cost["rop"]
        ret["red"] = bkz_cost["rop"]
        ret["svp"] = svp_cost["rop"]
        ret["beta"] = beta
        ret["eta"] = beta_params["eta"]
        ret["zeta"] = zeta
        ret["|S|"] = search_space
        ret["d"] = beta_params["d"]
        ret["prob"] = probability

        ret.register_impermanent(
            {"|S|": False},
            rop=True,
            red=True,
            svp=True,
            eta=False,
            zeta=False,
            prob=False,
        )

        # Repeat whole experiment ~1/prob times
        if probability and not RR(probability).is_NaN():
            ret = ret.repeat(
                prob_amplify(0.99, probability),
            )
        else:
            return Cost(rop=oo)
        return ret

    @classmethod
    def cost_zeta(
        cls,
        zeta: int,
        params: LWEParameters,
        red_shape_model=red_shape_model_default,
        red_cost_model=red_cost_model_default,
        m: int = oo,
        babai: bool = True,
        mitm: bool = True,
        optimize_d=True,
        poly_degree=None, # EDIT: we pass the polynomial degree for using rotations in power of two cyclotomics. If None, assume RLWE and poly_degree = n.
        mitm_heuristic="square root", # EDIT: we allow choosing between different heuristics for the speed up achieved by MITM
        log_level=5,
        **kwds,
    ):
        """
        This function optimizes costs for a fixed guessing dimension ζ.
        """
        # EDIT: zeta = 0 is now a special case
        if zeta == 0:
            # when zeta is zero, we don't want to use rotations. So we just call the standard primal hybrid cost.
            return PrimalHybrid.cost_zeta(zeta, params, red_shape_model, red_cost_model, m, babai, mitm, optimize_d, log_level, **kwds)
        
        # step 0. establish baseline
        baseline_cost = primal_usvp(
            params,
            red_shape_model=red_shape_model,
            red_cost_model=red_cost_model,
            optimize_d=False,
            log_level=log_level + 1,
            **kwds,
        )
        Logging.log("bdd", log_level, f"H0: {repr(baseline_cost)}")

        f = partial(
            cls.cost,
            params=params,
            zeta=zeta,
            babai=babai,
            mitm=mitm,
            red_shape_model=red_shape_model,
            red_cost_model=red_cost_model,
            m=m,
            poly_degree=poly_degree, # EDIT
            mitm_heuristic=mitm_heuristic, # EDIT
            **kwds,
        )

        if baseline_cost["rop"] == oo:
            # these parameters mean usvp does not succeed for any beta < max_beta_global,
            # so we search over the full beta range
            max_beta = max_beta_global
        else:
            max_beta = baseline_cost["beta"]

        # step 1. optimize β. If zeta > 0, optimize search space.
        # the cost curve with beta is non-smooth, with sudden jumps due to the search space changing. We eliminate
        # these jumps by instead fixing the search space, and finding the best attack for that search space.
        # we then loop over increasing search spaces to find the best overall attack.
        # our search space is formed of all zeta length strings of weight at most hw for some hw.
        # the smallest admissable hw
        min_hw = max(0, zeta - params.Xs.n + params.Xs.hamming_weight)
        # the largest admissable hw
        max_hw = min(zeta, params.Xs.hamming_weight)
        cost = Cost(rop=oo)
        for hw in range(min_hw, max_hw + 1):
            search_space, hit_probability = rot_guessing_set_and_hit_probability(zeta, params.Xs, hw, poly_degree)
            precision = 2
            with local_minimum(40, max_beta + precision, precision=precision, log_level=log_level + 1) as it:
                for beta in it:
                    it.update(f(beta, search_space=search_space, hit_probability=hit_probability))
                for beta in it.neighborhood:
                    it.update(f(beta, search_space=search_space, hit_probability=hit_probability))
                new_cost = it.y
            if new_cost["rop"] > cost["rop"]:
                # cost has started increasing, time to stop
                break
            else:
                cost = new_cost
        Logging.log("bdd", log_level, f"H1: {cost!r}")

        # step 2. optimize d
        if cost and cost.get("tag", "XXX") != "usvp" and optimize_d:
            with local_minimum(
                params.n - zeta, cost["d"] + 1, log_level=log_level + 1
            ) as it:
                for d in it:
                    it.update(f(beta=cost["beta"], d=d))
                cost = it.y
            Logging.log("bdd", log_level, f"H2: {cost!r}")

        if cost is None:
            return Cost(rop=oo)
        # print(f"{zeta=}, {cost=}", file=sys.stderr)
        return cost

    def __call__(
        self,
        params: LWEParameters,
        babai: bool = True,
        zeta: int = None,
        mitm: bool = True,
        red_shape_model=red_shape_model_default,
        red_cost_model=red_cost_model_default,
        poly_degree=None, # EDIT: we pass the polynomial degree for using rotations in power of two cyclotomics. If None, assume RLWE and poly_degree = n.
        mitm_heuristic="square root", # EDIT: we allow choosing between different heuristics for the speed up achieved by MITM
        log_level=1,
        **kwds,
    ):
        """
        Estimate the cost of the primal hybrid attack with rotations.

        :param params: LWE parameters.
        :param zeta: Guessing dimension ζ ≥ 0.
        :param babai: Insist on Babai's algorithm for finding close vectors.
        :param mitm: Simulate MITM approach (√ of search space).
        :param poly_degree: the polynomial degree for using rotations in power of two cyclotomics. If None, assume RLWE and poly_degree = n.
        :param mitm_heuristic: the heuristic to use for the speed up achieved by MITM. If `square root`, we assume a √ of the search space speed up. If `estimator`, we assume a √(poly_degree) * √(search_space) speed up. If mitm=False, this parameter is ignored.
        :return: A cost dictionary

        The returned cost dictionary has the following entries:

        - ``rop``: Total number of word operations (≈ CPU cycles).
        - ``red``: Number of word operations in lattice reduction.
        - ``δ``: Root-Hermite factor targeted by lattice reduction.
        - ``β``: BKZ block size.
        - ``η``: Dimension of the final BDD call.
        - ``ζ``: Number of guessed coordinates.
        - ``|S|``: Guessing search space.
        - ``prob``: Probability of success in guessing.
        - ``repeat``: How often to repeat the attack.
        - ``d``: Lattice dimension.
        """

        if zeta == 0:
            tag = "bdd"
        else:
            tag = "hybrid"

        params = LWEParameters.normalize(params)

        # allow for a larger embedding lattice dimension: Bai and Galbraith
        m = params.m + params.n if params.Xs <= params.Xe else params.m

        f = partial(
            self.cost_zeta,
            params=params,
            red_shape_model=red_shape_model,
            red_cost_model=red_cost_model,
            babai=babai,
            mitm=mitm,
            m=m,
            poly_degree=poly_degree, # EDIT
            mitm_heuristic=mitm_heuristic, # EDIT
            log_level=log_level + 1,
        )

        if zeta is None:
            # primal_hybrid cost is generally parabolic with zeta.
            # We find a range [min_zeta, max_zeta] such that cost is finite over the entire interval.

            # we search for min_zeta such that cost(min_zeta) is finite, but cost(min_zeta - 1) is infinite.
            cost_min_zeta = f(zeta=0, optimize_d=False, **kwds)
            if cost_min_zeta["rop"] < oo:
                min_zeta = 0
            else:
                min_zeta_lower = 0
                min_zeta_upper = params.n - 1
                min_zeta = (min_zeta_upper + min_zeta_lower) // 2
                while min_zeta_upper - min_zeta_lower > 1:
                    cost_min_zeta = f(min_zeta, optimize_d=False, **kwds)
                    if cost_min_zeta["rop"] < oo:
                        min_zeta_upper = min_zeta
                    else:
                        min_zeta_lower = min_zeta
                    min_zeta = (min_zeta_upper + min_zeta_lower) // 2

            # we search for max_zeta such that cost(max_zeta) is finite, but cost(max_zeta + 1) is infinite.
            cost_max_zeta = f(zeta=params.n-1, optimize_d=False, **kwds)
            if cost_max_zeta["rop"] < oo:
                max_zeta = params.n - 1
            else:
                max_zeta_lower = 0
                max_zeta_upper = params.n - 1
                max_zeta = (max_zeta_upper + max_zeta_lower) // 2
                while max_zeta_upper - max_zeta_lower > 1:
                    cost_max_zeta = f(max_zeta, optimize_d=False, **kwds)
                    if cost_max_zeta["rop"] < oo:
                        max_zeta_lower = max_zeta
                    else:
                        max_zeta_upper = max_zeta
                    max_zeta = (max_zeta_upper + max_zeta_lower) // 2

            ret = minimize_scalar(lambda x: log(f(zeta=round(x), optimize_d=False,
                                                  **kwds)["rop"]), bounds=(min_zeta, max_zeta), method="bounded")

            zeta = int(ret.x)
            cost = f(zeta=zeta, optimize_d=False, **kwds)
            # check a small neighborhood of this zeta
            precision = 3
            for zeta in range(max(0, zeta - precision), min(params.n, zeta + precision) + 1):
                cost = min(cost, f(zeta=zeta, optimize_d=False, **kwds))
            # minimize_scalar fits to a parabola. This can cause this search to miss minima at extrema
            cost = min(cost, cost_min_zeta, cost_max_zeta)

        else:
            cost = f(zeta=zeta)

        cost["tag"] = tag
        cost["problem"] = params

        if tag == "bdd":
            for k in ("|S|", "prob", "repetitions", "zeta"):
                try:
                    del cost[k]
                except KeyError:
                    pass

        return cost.sanity_check()

    __name__ = "rot_primal_hybrid"


rot_primal_hybrid = RotPrimalHybrid()


def primal_bdd(
    params: LWEParameters,
    red_shape_model=red_shape_model_default,
    red_cost_model=red_cost_model_default,
    log_level=1,
    **kwds,
):
    """
    Estimate the cost of the BDD approach as given in [RSA:LiuNgu13]_.

    :param params: LWE parameters.
    :param red_cost_model: How to cost lattice reduction
    :param red_shape_model: How to model the shape of a reduced basis

    """

    return rot_primal_hybrid(
        params,
        zeta=0,
        mitm=False,
        babai=False,
        red_shape_model=red_shape_model,
        red_cost_model=red_cost_model,
        log_level=log_level,
        **kwds,
    )
