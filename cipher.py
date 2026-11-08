"""
VH-Cascade Cipher  (Vigenere -> Hill)
=====================================
CT-486 Network and Information Security - Complex Computing Problem

A two-stage classical product cipher over the alphabet A-Z (Z_26):

    Stage 1 (polyalphabetic substitution):  V_i = (P_i + K_(i mod m))  mod 26
    Stage 2 (polygraphic linear substitution): [C_2t, C_2t+1]^T = H . [V_2t, V_2t+1]^T  mod 26

    Decryption reverses the stages:
    Stage 2^-1:  [V_2t, V_2t+1]^T = H^-1 . [C_2t, C_2t+1]^T  mod 26
    Stage 1^-1:  P_i = (V_i - K_(i mod m))  mod 26

Key  = Vigenere keyword (>= 10 letters)  +  4-letter Hill key (2x2 matrix, invertible mod 26)
"""

from math import gcd

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
MOD = 26
MIN_VIGENERE_KEY = 10
PAD_CHAR = "X"


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def clean(text: str) -> str:
    """Keep only A-Z (upper-cased). Spaces, digits and punctuation are dropped."""
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def to_nums(text: str) -> list:
    return [ord(ch) - 65 for ch in text]


def to_text(nums) -> str:
    return "".join(chr(int(n) % MOD + 65) for n in nums)


def mod_inverse(a: int, m: int = MOD) -> int:
    """Multiplicative inverse of a mod m (raises ValueError if it does not exist)."""
    a %= m
    if gcd(a, m) != 1:
        raise ValueError(f"{a} has no inverse mod {m}")
    return pow(a, -1, m)


def matrix_det(h) -> int:
    return (h[0][0] * h[1][1] - h[0][1] * h[1][0]) % MOD


def matrix_inverse(h):
    """Inverse of a 2x2 matrix mod 26:  H^-1 = det^-1 * adj(H)."""
    det_inv = mod_inverse(matrix_det(h))
    a, b = h[0]
    c, d = h[1]
    return [[(d * det_inv) % MOD, (-b * det_inv) % MOD],
            [(-c * det_inv) % MOD, (a * det_inv) % MOD]]


def matrix_from_key(hill_key: str):
    """'HILL' -> [[7, 8], [11, 11]]  (row-major)."""
    k = to_nums(clean(hill_key))
    if len(k) != 4:
        raise ValueError("Hill key must contain exactly 4 letters")
    h = [[k[0], k[1]], [k[2], k[3]]]
    if gcd(matrix_det(h), MOD) != 1:
        raise ValueError(f"Hill key '{hill_key}' gives det={matrix_det(h)}, not invertible mod 26")
    return h


def validate_key(vig_key: str, hill_key: str):
    vk = clean(vig_key)
    if len(vk) < MIN_VIGENERE_KEY:
        raise ValueError(f"Vigenere key must be at least {MIN_VIGENERE_KEY} letters (got {len(vk)})")
    return to_nums(vk), matrix_from_key(hill_key)


# ----------------------------------------------------------------------------
# Stage 1 : Vigenere
# ----------------------------------------------------------------------------
def vigenere(nums, key_nums, decrypt=False):
    m = len(key_nums)
    sign = -1 if decrypt else 1
    return [(p + sign * key_nums[i % m]) % MOD for i, p in enumerate(nums)]


# ----------------------------------------------------------------------------
# Stage 2 : Hill (2x2)
# ----------------------------------------------------------------------------
def hill(nums, h):
    out = []
    (a, b), (c, d) = h
    for i in range(0, len(nums), 2):
        x, y = nums[i], nums[i + 1]
        out.append((a * x + b * y) % MOD)
        out.append((c * x + d * y) % MOD)
    return out


# ----------------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------------
def encrypt(plaintext: str, vig_key: str, hill_key: str) -> str:
    k, h = validate_key(vig_key, hill_key)
    p = clean(plaintext)
    if len(p) % 2:                      # Hill works on digraphs -> pad to even length
        p += PAD_CHAR
    v = vigenere(to_nums(p), k)          # Stage 1
    c = hill(v, h)                       # Stage 2
    return to_text(c)


def decrypt(ciphertext: str, vig_key: str, hill_key: str, strip_pad=False) -> str:
    k, h = validate_key(vig_key, hill_key)
    c = clean(ciphertext)
    if len(c) % 2:
        raise ValueError("Ciphertext length must be even")
    v = hill(to_nums(c), matrix_inverse(h))   # undo Stage 2
    p = to_text(vigenere(v, k, decrypt=True))  # undo Stage 1
    if strip_pad and p.endswith(PAD_CHAR):
        p = p[:-1]
    return p


def encrypt_trace(plaintext: str, vig_key: str, hill_key: str):
    """Returns every intermediate value - used for the worked example in the report."""
    k, h = validate_key(vig_key, hill_key)
    p = clean(plaintext)
    if len(p) % 2:
        p += PAD_CHAR
    pn = to_nums(p)
    kn = [k[i % len(k)] for i in range(len(pn))]
    vn = vigenere(pn, k)
    cn = hill(vn, h)
    return {"P": p, "K": to_text(kn), "V": to_text(vn), "C": to_text(cn),
            "Pn": pn, "Kn": kn, "Vn": vn, "Cn": cn, "H": h, "Hinv": matrix_inverse(h)}


# ----------------------------------------------------------------------------
# Baseline: single-stage Shift (Caesar) cipher, for the efficiency comparison
# ----------------------------------------------------------------------------
def shift_encrypt(plaintext: str, k: int) -> str:
    return to_text([(x + k) % MOD for x in to_nums(clean(plaintext))])


def shift_decrypt(ciphertext: str, k: int) -> str:
    return to_text([(x - k) % MOD for x in to_nums(clean(ciphertext))])


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="VH-Cascade cipher (Vigenere -> Hill)")
    ap.add_argument("mode", choices=["enc", "dec"])
    ap.add_argument("text")
    ap.add_argument("--vkey", default="CYBERSECURITY", help="Vigenere keyword, >= 10 letters")
    ap.add_argument("--hkey", default="HILL", help="4-letter Hill key (invertible mod 26)")
    a = ap.parse_args()
    if a.mode == "enc":
        print(encrypt(a.text, a.vkey, a.hkey))
    else:
        print(decrypt(a.text, a.vkey, a.hkey))
