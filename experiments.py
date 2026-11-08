"""
Experiments for the report: attack success rates, computational effort and performance.
Run:  python experiments.py        -> results/results.json and results/*.png
"""

import json
import os
import random
import statistics
import time
from math import gcd

from cipher import clean, encrypt, decrypt, shift_encrypt, shift_decrypt, matrix_det
from attacks import known_plaintext_attack, frequency_analysis_attack, shift_brute_force, accuracy

random.seed(486)
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "results")
os.makedirs(OUT, exist_ok=True)
CORPUS = clean(open(os.path.join(HERE, "data", "sample_plaintext.txt"), encoding="latin-1").read())
ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def random_vig_key(lo=10, hi=16):
    return "".join(random.choice(ALPHA) for _ in range(random.randint(lo, hi)))


def random_hill_key():
    while True:
        k = "".join(random.choice(ALPHA) for _ in range(4))
        h = [[ord(k[0]) - 65, ord(k[1]) - 65], [ord(k[2]) - 65, ord(k[3]) - 65]]
        if gcd(matrix_det(h), 26) == 1:
            return k


def excerpt(n):
    if n % 2:
        n += 1
    start = random.randrange(0, len(CORPUS) - n)
    return CORPUS[start:start + n]


def experiment_kpa(trials=100, msg_len=1000, known_lengths=(10, 16, 20, 24, 30, 36, 40, 50, 60)):
    rows = []
    for L in known_lengths:
        ok, times, cands = 0, [], []
        for _ in range(trials):
            vk, hk = random_vig_key(), random_hill_key()
            p = excerpt(msg_len)
            c = encrypt(p, vk, hk)
            r = known_plaintext_attack(c, p[:L])
            success = r["success"] and r["plaintext"] == p
            ok += success
            times.append(r["time"])
            cands.append(r["candidates"])
        rows.append({"known_len": L, "success_rate": ok / trials,
                     "mean_time_ms": 1000 * statistics.mean(times), "mean_candidates": statistics.mean(cands)})
        print("KPA", rows[-1])
    return rows


def experiment_kpa_by_keylen(trials=60, msg_len=1000, key_lengths=(10, 11, 12, 13, 14, 15, 16, 20)):
    """Minimum known-plaintext length needed, per Vigenere key length."""
    rows = []
    for m in key_lengths:
        needed = []
        for _ in range(trials):
            vk, hk = random_vig_key(m, m), random_hill_key()
            p = excerpt(msg_len)
            c = encrypt(p, vk, hk)
            for L in range(4, 120, 2):
                r = known_plaintext_attack(c, p[:L])
                if r["success"] and r["plaintext"] == p:
                    needed.append(L)
                    break
        rows.append({"key_len": m, "min_known_mean": statistics.mean(needed), "min_known_max": max(needed)})
        print("KPA-key", rows[-1])
    return rows


def experiment_kpa_by_length(trials=50, known=50, lengths=(100, 200, 400, 800, 1000, 2000, 3000)):
    """KPA with a fixed 50-letter known prefix, for different total ciphertext lengths."""
    rows = []
    for n in lengths:
        ok, times = 0, []
        for _ in range(trials):
            vk, hk = random_vig_key(), random_hill_key()
            p = excerpt(n)
            r = known_plaintext_attack(encrypt(p, vk, hk), p[:known])
            ok += r["success"] and r["plaintext"] == p
            times.append(r["time"])
        rows.append({"length": n, "success_rate": ok / trials, "mean_time_ms": 1000 * statistics.mean(times)})
        print("KPA-len", rows[-1])
    return rows


def experiment_freq(trials=40, lengths=(100, 200, 300, 400, 600, 800, 1000, 1500, 2000, 3000)):
    rows = []
    for n in lengths:
        ok, accs, times, evals = 0, [], [], []
        for _ in range(trials):
            vk, hk = random_vig_key(), random_hill_key()
            p = excerpt(n)
            c = encrypt(p, vk, hk)
            r = frequency_analysis_attack(c)
            a = accuracy(r.get("plaintext", ""), p)
            ok += a >= 0.99
            accs.append(a)
            times.append(r["time"])
            evals.append(r["evaluations"])
        rows.append({"length": n, "success_rate": ok / trials, "mean_accuracy": statistics.mean(accs),
                     "mean_time_ms": 1000 * statistics.mean(times), "mean_evaluations": statistics.mean(evals)})
        print("FREQ", rows[-1])
    return rows


def experiment_freq_by_keylen(trials=30, n=800, key_lengths=(10, 13, 16, 20)):
    rows = []
    for m in key_lengths:
        ok = 0
        for _ in range(trials):
            vk, hk = random_vig_key(m, m), random_hill_key()
            p = excerpt(n)
            r = frequency_analysis_attack(encrypt(p, vk, hk), max_key_len=20)
            ok += accuracy(r.get("plaintext", ""), p) >= 0.99
        rows.append({"key_len": m, "success_rate": ok / trials})
        print("FREQ-key", rows[-1])
    return rows


def experiment_shift(trials=40, lengths=(20, 50, 100, 200, 400, 1000)):
    rows = []
    for n in lengths:
        ok, times = 0, []
        for _ in range(trials):
            k = random.randrange(1, 26)
            p = excerpt(n)
            r = shift_brute_force(shift_encrypt(p, k))
            ok += r["plaintext"] == p
            times.append(r["time"])
        rows.append({"length": n, "success_rate": ok / trials, "mean_time_ms": 1000 * statistics.mean(times)})
        print("SHIFT", rows[-1])
    return rows


def best_time(fn, repeats=5):
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def experiment_speed(lengths=(1_000, 10_000, 100_000, 1_000_000)):
    rows = []
    big = (CORPUS * 5)[:max(lengths)]
    vk, hk = "CYBERSECURITY", "HILL"
    for n in lengths:
        p = big[:n]
        c = encrypt(p, vk, hk)
        s = shift_encrypt(p, 3)
        reps = 5 if n <= 100_000 else 3
        row = {"length": n,
               "vh_enc_ms": 1000 * best_time(lambda: encrypt(p, vk, hk), reps),
               "vh_dec_ms": 1000 * best_time(lambda: decrypt(c, vk, hk), reps),
               "shift_enc_ms": 1000 * best_time(lambda: shift_encrypt(p, 3), reps),
               "shift_dec_ms": 1000 * best_time(lambda: shift_decrypt(s, 3), reps)}
        rows.append(row)
        print("SPEED", row)
    return rows


if __name__ == "__main__":
    import platform
    results = {
        "environment": {"python": platform.python_version(), "machine": platform.machine(),
                        "processor": platform.processor() or "n/a", "cpus": os.cpu_count()},
        "kpa": experiment_kpa(),
        "kpa_by_keylen": experiment_kpa_by_keylen(),
        "kpa_by_length": experiment_kpa_by_length(),
        "freq": experiment_freq(),
        "freq_by_keylen": experiment_freq_by_keylen(),
        "shift": experiment_shift(),
        "speed": experiment_speed(),
    }
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(results, f, indent=2)
    print("saved results/results.json")
