"""Draws the report figures from results/results.json."""
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "results")
R = json.load(open(os.path.join(OUT, "results.json")))

BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"],
    "font.size": 11, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": MUTED,
    "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.8, "legend.frameon": False,
})


def save(fig, name):
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, name), dpi=220)
    plt.close(fig)


# Figure 1 - ciphertext-only attack success vs length (VH-Cascade vs Shift)
fig, ax = plt.subplots(figsize=(6, 3.8))
f = R["freq"]
s = R["shift"]
ax.plot([r["length"] for r in f], [100 * r["success_rate"] for r in f], color=BLUE, lw=2, marker="o", ms=6,
        label="VH-Cascade (IC + frequency attack)")
ax.plot([r["length"] for r in f], [100 * r["mean_accuracy"] for r in f], color=AQUA, lw=2, marker="s", ms=6,
        ls="--", label="VH-Cascade mean letters recovered")
ax.plot([r["length"] for r in s], [100 * r["success_rate"] for r in s], color=ORANGE, lw=2, marker="^", ms=6,
        label="Shift cipher (brute force)")
ax.set_xlabel("Ciphertext length (letters)")
ax.set_ylabel("Success (%)")
ax.set_ylim(-3, 105)
ax.legend(loc="lower right", fontsize=9)
save(fig, "fig1_freq_success.png")

# Figure 2 - known-plaintext attack success vs known length
fig, ax = plt.subplots(figsize=(6, 3.8))
k = R["kpa"]
ax.plot([r["known_len"] for r in k], [100 * r["success_rate"] for r in k], color=BLUE, lw=2, marker="o", ms=6)
for r in k:
    if r["known_len"] in (20, 30, 40):
        ax.annotate(f'{100 * r["success_rate"]:.0f}%', (r["known_len"], 100 * r["success_rate"]),
                    textcoords="offset points", xytext=(-14, 8), fontsize=9, color=INK)
ax.set_xlabel("Known plaintext available (letters)")
ax.set_ylabel("Full recovery (%)")
ax.set_ylim(-3, 108)
save(fig, "fig2_kpa_success.png")

# Figure 3 - encryption / decryption time vs input size (log-log)
fig, ax = plt.subplots(figsize=(6, 3.8))
sp = R["speed"]
n = [r["length"] for r in sp]
ax.plot(n, [r["vh_enc_ms"] for r in sp], color=BLUE, lw=2, marker="o", ms=6, label="VH-Cascade encrypt")
ax.plot(n, [r["vh_dec_ms"] for r in sp], color=AQUA, lw=2, marker="s", ms=6, ls="--", label="VH-Cascade decrypt")
ax.plot(n, [r["shift_enc_ms"] for r in sp], color=ORANGE, lw=2, marker="^", ms=6, label="Shift encrypt")
ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlabel("Message length (letters)")
ax.set_ylabel("Time (ms)")
ax.legend(loc="upper left", fontsize=9)
save(fig, "fig3_speed.png")

# Figure 4 - known plaintext needed per Vigenere key length
fig, ax = plt.subplots(figsize=(6, 3.8))
kk = R["kpa_by_keylen"]
labels = [str(r["key_len"]) for r in kk]
vals = [r["min_known_mean"] for r in kk]
colors = [ORANGE if r["key_len"] % 2 else BLUE for r in kk]
bars = ax.bar(labels, vals, color=colors, width=0.6)
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 0.8, f"{v:.0f}", ha="center", fontsize=9, color=INK)
ax.set_xlabel("Vigenere key length m (blue = even, orange = odd)")
ax.set_ylabel("Known letters needed (mean)")
ax.grid(axis="x", visible=False)
ax.set_axisbelow(True)
save(fig, "fig4_kpa_keylen.png")
# Figure 0 - letter frequencies: English vs VH-Cascade ciphertext (frequency analysis of the ciphertext)
import numpy as np
from cipher import clean, encrypt, to_nums
from attacks import ENGLISH_FREQ
text = clean(open(os.path.join(HERE, "data", "sample_plaintext.txt"), encoding="latin-1").read())
ct = encrypt(text[30000:33000], "CYBERSECURITY", "HILL")
cf = np.bincount(to_nums(ct), minlength=26) / len(ct)
x = np.arange(26)
fig, ax = plt.subplots(figsize=(7.2, 3.4))
ax.bar(x - 0.21, 100 * ENGLISH_FREQ, width=0.4, color=BLUE, label="Expected English")
ax.bar(x + 0.21, 100 * cf, width=0.4, color=ORANGE, label="VH-Cascade ciphertext (3,000 letters)")
ax.axhline(100 / 26, color=MUTED, lw=1, ls="--", label="Uniform (random) 3.85%")
ax.set_xticks(x)
ax.set_xticklabels(list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
ax.set_ylabel("Frequency (%)")
ax.grid(axis="x", visible=False)
ax.set_axisbelow(True)
ax.legend(loc="upper right", fontsize=9)
save(fig, "fig0_letter_freq.png")
print("charts saved")
