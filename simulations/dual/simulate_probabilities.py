import numpy as np
import matplotlib.pyplot as plt
from sage.all import RR, binomial, exp, log, round
from tqdm import tqdm # type: ignore

# from https://github.com/kevin-carrier/CodedDualAttack/blob/main/OptimizeCodedDualAttack/utilitaries.py
def compute_p0(alpha):
	# Centered Binomial distribution
	assert(alpha == 2 or alpha==3)
	prob_B2=[6/16, 4/16, 1/16]
	prob_B3=[20/64, 15/64, 6/64, 1/64]
	if alpha == 2:
		p0 = prob_B2[0]
	else:
		p0 = prob_B3[0]
	return RR(p0)

# from https://github.com/kevin-carrier/CodedDualAttack/blob/main/OptimizeCodedDualAttack/utilitaries.py
def compute_eta(R, alpha, nenu, nfft):
	res = RR(1.0)
	p0 = RR(compute_p0(alpha))
	
	binom_binom = RR(1.0)
	prob_binom = RR(RR(1.0 - p0)**RR(nenu + nfft))
	for t in range(nenu):
		res -= RR(binom_binom * prob_binom)
		binom_binom *= RR(nenu + nfft - t)
		binom_binom /= RR(t + 1.0)
		prob_binom *= p0
		prob_binom /= RR(1.0 - p0)

	binom_bis = RR(1.0/binomial(nenu+nfft, nenu))
	for t in range(nenu, nenu+nfft+1):
		#res -= RR( RR( RR( RR(1.0) - RR(binom_bis) )**RR(R) ) * binom_binom * prob_binom)
		res -= RR( RR(exp( RR(R)*RR(log(RR(1.0) - RR(binom_bis))) )) * binom_binom * prob_binom)
		
		binom_bis *= RR(t + 1.0)
		binom_bis /= RR(t + 1.0 - nenu)
		binom_bis = min(RR(1.0), binom_bis)
		binom_binom *= RR(nenu + nfft - t)
		binom_binom /= RR(t + 1.0)
		prob_binom *= p0
		prob_binom /= RR(1.0 - p0)
	return RR(res)

# adapted from the above
def compute_eta_rot(R, alpha, nenu, N):
	res = RR(1.0)
	p0 = RR(compute_p0(alpha))
	
	binom_binom = RR(1.0)
	prob_binom = RR(RR(1.0 - p0)**RR(N))
	for t in range(nenu):
		res -= RR(binom_binom * prob_binom)
		binom_binom *= RR(N - t)
		binom_binom /= RR(t + 1.0)
		prob_binom *= p0
		prob_binom /= RR(1.0 - p0)

	binom_bis = RR(1.0/binomial(N, nenu))
	for t in range(nenu, N + 1):
		#res -= RR( RR( RR( RR(1.0) - RR(binom_bis) )**RR(R) ) * binom_binom * prob_binom)
		res -= RR( RR(exp( RR(R)*RR(log(RR(1.0) - RR(binom_bis))) )) * binom_binom * prob_binom)
		
		binom_bis *= RR(t + 1.0)
		binom_bis /= RR(t + 1.0 - nenu)
		binom_bis = min(RR(1.0), binom_bis)
		binom_binom *= RR(N - t)
		binom_binom /= RR(t + 1.0)
		prob_binom *= p0
		prob_binom /= RR(1.0 - p0)
	return RR(res)

num_trials = 10000
print(f"{num_trials=}")

# logn, k, alpha, n_e, n_f, max_R
kyber_512_sets = [(8, 2, 3, 7, 51, 2 ** 10), (8, 2, 3, 4, 48, 2 ** 10), (8, 2, 3, 1, 38, 2 ** 10)]
kyber_768_sets = [(8, 3, 2, 22, 93, 1763491512), (8, 3, 2, 16, 86, 13077651), (8, 3, 2, 6, 69, 271)]
kyber_1024_sets = [(8, 4, 2, 26, 133, 89176064548), (8, 4, 2, 14, 133, 689643), (8, 4, 2, 18, 101, 34873734)]

# these are the sets from CMST25
former_kyber_512_sets = [(8, 2, 3, 1, 38, round(2 ** 2.84)), (8, 2, 3, 5, 52, round(2 ** 9.39)), (8, 2, 3, 4, 48, round(2 ** 7.71))]
former_kyber_768_sets = [(8, 3, 2, 6, 69, round(2 ** 9.49)), (8, 3, 2, 6, 93, round(2 ** 9.49)), (8, 3, 2, 8, 86, round(2 ** 12.32))]
former_kyber_1024_sets = [(8, 4, 2, 9, 100, round(2 ** 13.74)), (8, 4, 2, 10, 131, round(2 ** 15.15)), (8, 4, 2, 6, 132, round(2 ** 9.49))]

for (logn, k, alpha, n_e, n_f, max_R) in kyber_512_sets + kyber_768_sets + kyber_1024_sets + former_kyber_512_sets + former_kyber_768_sets + former_kyber_1024_sets:
    # make experiments run in reasonable time
    if max_R > 2 ** 10:
        max_R = 2 ** 10
    max_R = int(max_R)
    print(f"{logn=}, {k=}, {alpha=}, {n_e=}, {n_f=}, {max_R=}")
    
    n = 2 ** logn
    n_total = n * k
    n_tilde = n_e + n_f
    hit_counts = np.zeros(max_R)

    for trial in tqdm(range(num_trials)):
        R_sets = np.array([np.random.choice(n_tilde, size=n_e, replace=False) for _ in range(max_R)])
        # only sample the key bits corresponding to the n_tilde positions, since without rotations the other bits don't matter
        key = np.random.binomial(2 * alpha, 0.5, n_tilde) - alpha
        for i in range(max_R):
            R_set = R_sets[i]
            if np.all(key[R_set] == 0):
                hit_counts[i:] += 1
                break
    
    no_rot_probabilities = hit_counts / num_trials
    no_rot_probabilities = no_rot_probabilities.tolist()
    
    # now instantiate surrounding module structure
    rot_hit_counts = np.zeros(max_R)
    

    for trial in tqdm(range(num_trials)):
        # sample the entire key
        key = np.random.binomial(2 * alpha, 0.5, n_total) - alpha
        n_lat = n_total - n_tilde
        # choose n_lat random columns to fix
        I_lat = np.random.choice(n_total, size=n_lat, replace=False)
        # the remaining indices
        I_tilde = np.setdiff1d(np.arange(n_total), I_lat)
        
        # select R random subsets of size n_e from I_tilde
        R_sets = np.array([np.random.choice(I_tilde, size=n_e, replace=False) for _ in range(max_R)])
        # select a random rotation for each of the R sets
        rotations = np.random.randint(0, n, max_R)
        
        for i in range(max_R):
            # we rotate the indices of the R_set by the corresponding rotation, and check if the key is zero at those indices
            rows = n * (R_sets[i] // n)
            cols = R_sets[i] - rows
            # rotate
            np.add(cols, rotations[i], out=cols)
            np.mod(cols, n, out=cols)
            # add back the rows
            np.add(rows, cols, out=R_sets[i])
            if np.all(key[R_sets[i]] == 0):
                rot_hit_counts[i:] += 1
                break
    
    rot_probabilities = rot_hit_counts / num_trials
    rot_probabilities = rot_probabilities.tolist()
    
    x = np.arange(1, max_R + 1)
    predicted_no_rot_probabilities = [compute_eta(R + 1, alpha, n_e, n_f) for R in range(max_R)]
    plt.clf()
    plt.plot(x, no_rot_probabilities, label="observed, no rotations")
    plt.plot(x, predicted_no_rot_probabilities, '--', label="predicted, no rotations")
    
    plt.plot(x, rot_probabilities, label="observed, with rotations")
    predicted_rot_probabilities_rough = [1 - (1 - compute_p0(alpha) ** n_e) ** (R + 1) for R in range(max_R)]
    plt.plot(x, predicted_rot_probabilities_rough, '--', label="predicted, rough, with rotations")
    predicted_rot_probabilities = [compute_eta_rot(R + 1, alpha, n_e, n_total) for R in range(max_R)]
    plt.plot(x, predicted_rot_probabilities, '--', label="predicted, with rotations")
    plt.legend()
    
    # save with log_max_R to 2 d.p.
    log_max_R = int(round(100 * log(max_R, 2))) / 100
    plt.savefig(f"{logn}_{k}_{alpha}_{n_e}_{n_f}_{log_max_R}.png")
    
    no_rot_coords = list(zip(x, no_rot_probabilities))
    no_rot_predicted_coords = list(zip(x, predicted_no_rot_probabilities))
    rot_coords = list(zip(x, rot_probabilities))
    rot_predicted_coords = list(zip(x, predicted_rot_probabilities))
    # leave out the 1 - (1 - p0 ** n_e) ** R prediction since it's a bit optimistic
    # rot_predicted_rough_coords = list(zip(x, predicted_rot_probabilities_rough))
    
    print(f"{no_rot_coords=}")
    print(f"{no_rot_predicted_coords=}")
    print(f"{rot_coords=}")
    print(f"{rot_predicted_coords=}")
    # print(f"{rot_predicted_rough_coords=}")
    print()