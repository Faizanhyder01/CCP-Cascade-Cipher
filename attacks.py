"""
Attacks on the VH-Cascade cipher (Vigenere -> Hill).

1. known_plaintext_attack(ciphertext, known_prefix)
       Linear-algebra attack. Needs a short plaintext/ciphertext prefix and recovers
       the Hill matrix, the Vigenere key (including its length) and the full message.

2. frequency_analysis_attack(ciphertext)
       Ciphertext-only attack. Uses the Index of Coincidence (IC) to find the rows of
       H^-1 one at a time, then letter-frequency analysis against the English
       distribution to recover the Vigenere shifts.

3. shift_brute_force(ciphertext)
       Baseline: breaking the single-stage Shift cipher (26 keys + frequency score).
"""

from itertools import product
from math import gcd
import time

import numpy as np

from cipher import MOD, clean, to_nums, to_text, matrix_det, matrix_inverse, mod_inverse, hill, vigenere

# Expected English letter frequencies (%), A..Z
ENGLISH_FREQ = np.array([
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025, 2.406,
    6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]) / 100.0
IC_ENGLISH = float(np.sum(ENGLISH_FREQ ** 2))   # ~0.0655
IC_RANDOM = 1.0 / 26                              # ~0.0385

# 30 most common English bigrams - used only to choose between the final few candidates
COMMON_BIGRAMS = set("TH HE IN ER AN RE ON AT EN ND TI ES OR TE OF ED IS IT AL AR "
                     "ST TO NT NG SE HA AS OU IO LE".split())

UNITS = [u for u in range(1, 26) if gcd(u, 26) == 1]   # 12 invertible multipliers mod 26


# ----------------------------------------------------------------------------
# Scoring helpers
# ----------------------------------------------------------------------------
def index_of_coincidence(nums) -> float:
    n = len(nums)
    if n < 2:
        return 0.0
    counts = np.bincount(np.asarray(nums), minlength=26)
    return float(np.sum(counts * (counts - 1)) / (n * (n - 1)))


def chi_squared(nums) -> float:
    counts = np.bincount(np.asarray(nums), minlength=26)
    expected = ENGLISH_FREQ * len(nums)
    return float(np.sum((counts - expected) ** 2 / expected))


def best_shift(column) -> int:
    """Shift s that makes (column - s) look most like English (max frequency correlation)."""
    counts = np.bincount(np.asarray(column), minlength=26)
    scores = [np.dot(np.roll(counts, -s), ENGLISH_FREQ) for s in range(26)]
    return int(np.argmax(scores))


def bigram_score(text: str) -> float:
    if len(text) < 2:
        return 0.0
    hits = sum(1 for i in range(len(text) - 1) if text[i:i + 2] in COMMON_BIGRAMS)
    return hits / (len(text) - 1)


def accuracy(a: str, b: str) -> float:
    n = max(len(a), len(b))
    return sum(1 for x, y in zip(a, b) if x == y) / n if n else 1.0


# ----------------------------------------------------------------------------
# 1. Known-plaintext attack
# ----------------------------------------------------------------------------
def _solve_mod_prime(dps, dcs, p):
    """Solve H . dP = dC  (mod prime p) from the first pair of linearly independent dP."""
    n = len(dps)
    for i in range(n):
        for j in range(i + 1, n):
            a, b = dps[i], dps[j]
            det = (a[0] * b[1] - a[1] * b[0]) % p
            if det == 0:
                continue
            det_inv = pow(det, -1, p)
            # X = [a b] (columns),  X^-1 = det^-1 [[b1, -b0], [-a1, a0]]
            xinv = [[b[1] * det_inv % p, -b[0] * det_inv % p],
                    [-a[1] * det_inv % p, a[0] * det_inv % p]]
            y = [[dcs[i][0], dcs[j][0]], [dcs[i][1], dcs[j][1]]]   # [dC_i dC_j]
            return [[(y[r][0] * xinv[0][c] + y[r][1] * xinv[1][c]) % p for c in range(2)] for r in range(2)]
    return None


def _crt(h2, h13):
    """Combine a matrix mod 2 and a matrix mod 13 into one matrix mod 26."""
    return [[next(x for x in range(26) if x % 2 == h2[r][c] and x % 13 == h13[r][c]) for c in range(2)]
            for r in range(2)]


def known_plaintext_attack(ciphertext: str, known_prefix: str, max_key_len: int = 30, min_checks: int = 2):
    """
    Model:  C_t = H . (P_t + K_t)  =  H.P_t + H.K_t ,   t = digraph index
    K_t repeats every q = m / gcd(m, 2) digraphs, so for two digraphs q apart:
            C_(t+q) - C_t = H . (P_(t+q) - P_t)          <- the key cancels out
    Each such difference is a linear equation in the 4 unknown entries of H.
    The attacker does not know m, so every m = 1..max_key_len is tried.
    """
    t0 = time.perf_counter()
    c = to_nums(clean(ciphertext))
    p = to_nums(clean(known_prefix))
    nb = min(len(p), len(c)) // 2
    C = [(c[2 * t], c[2 * t + 1]) for t in range(nb)]
    P = [(p[2 * t], p[2 * t + 1]) for t in range(nb)]
    candidates_tried = 0

    for m in range(1, max_key_len + 1):
        candidates_tried += 1
        q = m // gcd(m, 2)
        if nb - q < 2 + min_checks or nb < q:
            continue
        dps = [((P[t + q][0] - P[t][0]) % 26, (P[t + q][1] - P[t][1]) % 26) for t in range(nb - q)]
        dcs = [((C[t + q][0] - C[t][0]) % 26, (C[t + q][1] - C[t][1]) % 26) for t in range(nb - q)]
        h2 = _solve_mod_prime(dps, dcs, 2)
        h13 = _solve_mod_prime(dps, dcs, 13)
        if h2 is None or h13 is None:
            continue
        H = _crt(h2, h13)
        if gcd(matrix_det(H), 26) != 1:
            continue
        # verify H against every difference equation
        ok = all(((H[0][0] * dp[0] + H[0][1] * dp[1]) % 26, (H[1][0] * dp[0] + H[1][1] * dp[1]) % 26) == dc
                 for dp, dc in zip(dps, dcs))
        if not ok:
            continue
        # recover the key:  K_t = H^-1 . C_t - P_t
        Hinv = matrix_inverse(H)
        key = [None] * m
        consistent = True
        for t in range(nb):
            v = hill(list(C[t]), Hinv)
            for j in range(2):
                pos = (2 * t + j) % m
                kval = (v[j] - P[t][j]) % 26
                if key[pos] is None:
                    key[pos] = kval
                elif key[pos] != kval:
                    consistent = False
                    break
            if not consistent:
                break
        if not consistent or None in key:
            continue
        plaintext = to_text(vigenere(hill(c, Hinv), key, decrypt=True))
        return {"success": True, "key_len": m, "vig_key": to_text(key), "H": H, "plaintext": plaintext,
                "candidates": candidates_tried, "time": time.perf_counter() - t0}
    return {"success": False, "candidates": candidates_tried, "time": time.perf_counter() - t0}


# ----------------------------------------------------------------------------
# 2. Ciphertext-only frequency-analysis attack
# ----------------------------------------------------------------------------
def _column_ic_matrix(S, q):
    """Average column IC for every candidate row at period q.  S: (rows, nb) array of letters."""
    rows, nb = S.shape
    cols = nb // q
    if cols < 2:
        return None
    T = S[:, :cols * q].reshape(rows, cols, q)
    counts = np.zeros((rows, q, 26), dtype=np.int32)
    for letter in range(26):
        counts[:, :, letter] = (T == letter).sum(axis=1)
    coinc = (counts * (counts - 1)).sum(axis=(1, 2))
    pairs = q * cols * (cols - 1)
    return coinc / pairs


def _period_and_key(stream, max_period):
    """Classic Vigenere break: IC -> period, frequency correlation -> each shift."""
    stream = np.asarray(stream)
    ics = []
    for m in range(1, max_period + 1):
        cols = [stream[i::m] for i in range(m)]
        ics.append(np.mean([index_of_coincidence(col) for col in cols]))
    best = max(ics)
    threshold = IC_RANDOM + 0.75 * (best - IC_RANDOM)
    m = next(i + 1 for i, v in enumerate(ics) if v >= threshold)
    key = [best_shift(stream[i::m]) for i in range(m)]
    return m, key


def frequency_analysis_attack(ciphertext: str, max_key_len: int = 20, keep_scalings: int = 3):
    """
    Idea: decrypting with ONE correct row r of H^-1 gives r.C_t = P_2t + K_(2t)  (or the odd letter).
    That stream is English under a periodic Caesar shift, so its column IC is ~0.066,
    whatever the shifts are.  A wrong row gives a near-random stream (IC ~0.038).
    So the 26 x 26 = 676 possible rows can be tested one by one instead of the
    157,248 possible matrices - the two stages are attacked separately ("divide and conquer").
    """
    t0 = time.perf_counter()
    c = np.array(to_nums(clean(ciphertext)), dtype=np.int16)
    c0, c1 = c[0::2], c[1::2]
    max_q = max_key_len  # q = m/gcd(m,2) <= m

    # Step 1 - every row with gcd(r0, r1, 26) = 1 (others cannot be part of an invertible matrix)
    rows = [(a, b) for a, b in product(range(26), repeat=2) if gcd(gcd(a, b), 26) == 1]
    R = np.array(rows, dtype=np.int16)
    S = (R[:, :1] * c0[None, :] + R[:, 1:] * c1[None, :]) % 26          # (rows, nb)

    # Step 2 - IC test for every (row, period q)
    ic_table = []
    for q in range(1, max_q + 1):
        v = _column_ic_matrix(S, q)
        if v is None:
            break
        ic_table.append(v)
    ic_table = np.array(ic_table)               # (periods, rows)
    row_score = ic_table.max(axis=0)
    order = np.argsort(-row_score)
    evaluations = ic_table.size

    # Step 3 - pick two row classes (rows equal up to a unit multiple share the same IC)
    def same_class(r, s):
        return any(((u * s[0]) % 26, (u * s[1]) % 26) == r for u in UNITS)

    ra = rows[order[0]]
    rb = None
    for idx in order[1:]:
        cand = rows[idx]
        if same_class(cand, ra):
            continue
        if gcd((ra[0] * cand[1] - ra[1] * cand[0]) % 26, 26) == 1:
            rb = cand
            break
    if rb is None:
        return {"success": False, "time": time.perf_counter() - t0, "evaluations": evaluations}

    # Step 4 - for each class, rank the 12 unit scalings by English-likeness of the de-shifted stream
    def scalings(r):
        idx = rows.index(r)
        q = int(np.argmax(ic_table[:, idx] >= IC_RANDOM + 0.75 * (ic_table[:, idx].max() - IC_RANDOM))) + 1
        base = S[idx].astype(int)
        ranked = []
        for u in UNITS:
            st = (u * base) % 26
            shifts = [best_shift(st[i::q]) for i in range(q)]
            plain = np.concatenate([(st[i::q] - shifts[i]) % 26 for i in range(q)])
            ranked.append((chi_squared(plain), ((u * r[0]) % 26, (u * r[1]) % 26)))
        ranked.sort()
        return [r_ for _, r_ in ranked[:keep_scalings]]

    cand_a, cand_b = scalings(ra), scalings(rb)

    # Step 5 - try both row orders, undo Hill, break the Vigenere stage, keep the most English result
    best = None
    for xa in cand_a:
        for xb in cand_b:
            for even, odd in ((xa, xb), (xb, xa)):
                Hinv = [list(even), list(odd)]
                v = hill(c.tolist(), Hinv)
                m, key = _period_and_key(v, max_key_len)
                plain = to_text(vigenere(v, key, decrypt=True))
                s = bigram_score(plain)
                evaluations += 1
                if best is None or s > best[0]:
                    best = (s, plain, Hinv, key, m)
    s, plain, Hinv, key, m = best
    H = matrix_inverse(Hinv)
    return {"success": True, "plaintext": plain, "H": H, "vig_key": to_text(key), "key_len": m,
            "score": s, "evaluations": evaluations, "time": time.perf_counter() - t0}


# ----------------------------------------------------------------------------
# 3. Baseline - Shift cipher brute force
# ----------------------------------------------------------------------------
def shift_brute_force(ciphertext: str):
    t0 = time.perf_counter()
    c = np.array(to_nums(clean(ciphertext)))
    scores = [chi_squared((c - k) % 26) for k in range(26)]
    k = int(np.argmin(scores))
    return {"key": k, "plaintext": to_text((c - k) % 26), "evaluations": 26, "time": time.perf_counter() - t0}
