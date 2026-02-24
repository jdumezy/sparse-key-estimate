import numpy as np
import matplotlib.pyplot as plt
from sage.all import RR, binomial, exp, log, oo
from tqdm import tqdm # type: ignore

num_trials = 10000
print(f"{num_trials=}")

for (logn, h, logzeta, k) in [(10, 64, 8, 2), (8, 32, 8, 4), (9, 64, 8, 3), (14, 64, 12, 1), (15, 192, 12, 1)]:
    print(f"{logn=}, {h=}, {logzeta=}, {k=}")
    n = 2 ** logn
    zeta = 2 ** logzeta
    key_length = n * k
    
    min_hw = max(0, zeta - key_length + h)
    max_hw = min(zeta, h)
    base = 2 # ternary
    hit_counts = np.zeros(max_hw + 1)
    
    # instantiate surrounding module structure
    rot_hit_counts = np.zeros(max_hw + 1)
    for trial in tqdm(range(num_trials)):

        # choose a random ternary key with h non zeroes
        key = np.zeros(key_length)
        non_zeroes = np.random.choice(key_length, h, replace=False)
        key[non_zeroes] = np.random.choice(np.array([-1, 1]), size=h)
        # we store the non-zero indices of the key in a boolean array for cheaper operations later
        key_non_zeroes_bool = np.zeros(key_length, dtype=bool)
        key_non_zeroes_bool[non_zeroes] = True
        
        # choose a random set to guess
        guessing_set = np.random.choice(key_length, size=zeta, replace=False)
        
        # we rotate the guessing set relative to the key, which is equivalent to rotating the key relative to the guessing set
        rows = n * (guessing_set // n)
        cols = guessing_set - rows
        rot_guessing_set = np.empty_like(guessing_set)
        key_non_zero_at_rot_guessing_set = np.empty_like(guessing_set, dtype=np.bool_)

        # now we search for the smallest weight of the random entries as we rotate the key
        hw = oo
        for j in range(n):
            # shift the guessing set by one inside each row
            np.add(cols, 1, out=cols)
            np.mod(cols, n, out=cols)
            np.add(rows, cols, out=rot_guessing_set)
            # gather key values at rotated_guessing_set indices
            np.take(key_non_zeroes_bool, rot_guessing_set, out=key_non_zero_at_rot_guessing_set)
            rot_hw = int(key_non_zero_at_rot_guessing_set.sum())
            hw = min(rot_hw, hw)
            if hw == 0:
                # can't get any lower that this
                break
        # we would have hit this key for any weight >= hw
        rot_hit_counts[hw:] += 1
        
    rot_probabilities = rot_hit_counts[min_hw:] / num_trials
    rot_probabilities = rot_probabilities.tolist()
    print(f"{rot_probabilities=}")
    log_rot_probabilities = [RR(log(probability, 2)) for probability in rot_probabilities]
    print(f"{log_rot_probabilities=}")
    
    # now find how large S(hw) is in both the plain and rotated algorithms.
    log_search_spaces = []
    log_probabilities = []
    search_space = 0
    probability = 0
    for hw in range(min_hw, max_hw + 1):
        search_space += binomial(zeta, hw) * base ** hw
        probability += binomial(key_length - zeta, h - hw) * binomial(zeta, hw) / binomial(key_length, h)
        log_search_spaces.append(RR(log(search_space, 2)))
        log_probabilities.append(RR(log(probability, 2)))

    # our rotation search spaces are n times larger than in the plain case
    log_rot_search_spaces = [logn + log_search_space for log_search_space in log_search_spaces]
    # and assuming independence between the rotated segments, our probabilities are 1 - (1 - p) ** n
    rot_heur_probabilities = [1 - (1 - 2 ** log_probability) ** n for log_probability in log_probabilities]
    log_rot_heur_probabilities = [RR(log(probability, 2)) for probability in rot_heur_probabilities]

    no_rot_coords = list(zip(log_search_spaces, log_probabilities))
    rot_coords = list(zip(log_rot_search_spaces, log_rot_probabilities))
    rot_heur_coords = list(zip(log_rot_search_spaces, log_rot_heur_probabilities))
    print(f"{no_rot_coords=}")
    print(f"{rot_coords=}")
    print(f"{rot_heur_coords=}")
    plt.plot(log_search_spaces, log_probabilities, label="probability, no rotations")
    
    plt.plot(log_rot_search_spaces, log_rot_probabilities, label="observed probabilities, rotations")
    plt.plot(log_rot_search_spaces, log_rot_heur_probabilities, 'kx', label="predicted probabilties, rotations")
    plt.legend()
    plt.savefig(f"{logn}_{h}_{logzeta}_{k}_{num_trials}.png")
    plt.clf()
    print()
            