"""
Interactive demo of the VH-Cascade cipher and both attacks.
    python main.py                       -> full demo with default keys
    python main.py --vkey MYSECRETKEY --hkey HILL --text "your message"
"""
import argparse
import os

from cipher import clean, encrypt, decrypt, encrypt_trace
from attacks import known_plaintext_attack, frequency_analysis_attack, accuracy

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vkey", default="CYBERSECURITY", help="Vigenere keyword (>= 10 letters)")
    ap.add_argument("--hkey", default="HILL", help="4-letter Hill key, invertible mod 26")
    ap.add_argument("--text", default="Meet me at the NED gate at noon")
    ap.add_argument("--known", type=int, default=40, help="known-plaintext letters given to the KPA")
    ap.add_argument("--length", type=int, default=1000, help="message length for the attack demo")
    a = ap.parse_args()

    print("=" * 70, "\n1) ENCRYPTION / DECRYPTION\n" + "=" * 70)
    t = encrypt_trace(a.text, a.vkey, a.hkey)
    print(f"Plaintext   P : {t['P']}")
    print(f"Key stream  K : {t['K']}")
    print(f"Stage 1     V : {t['V']}   (Vigenere: V = P + K mod 26)")
    print(f"Stage 2     C : {t['C']}   (Hill: C = H.V mod 26, H = {t['H']})")
    print(f"Decrypted     : {decrypt(t['C'], a.vkey, a.hkey)}   (H^-1 = {t['Hinv']})")

    text = clean(open(os.path.join(HERE, "data", "sample_plaintext.txt"), encoding="latin-1").read())
    p = text[20000:20000 + a.length]
    c = encrypt(p, a.vkey, a.hkey)

    print("\n" + "=" * 70, "\n2) KNOWN-PLAINTEXT ATTACK\n" + "=" * 70)
    r = known_plaintext_attack(c, p[:a.known])
    if r["success"]:
        print(f"Recovered H = {r['H']}, Vigenere key = {r['vig_key']} (length {r['key_len']})")
        print(f"Full message recovered: {r['plaintext'] == p}  | time {1000 * r['time']:.2f} ms")
    else:
        print("Attack failed - give it more known plaintext (--known)")

    print("\n" + "=" * 70, "\n3) CIPHERTEXT-ONLY FREQUENCY ANALYSIS ATTACK\n" + "=" * 70)
    r = frequency_analysis_attack(c)
    print(f"Recovered H = {r.get('H')}, Vigenere key = {r.get('vig_key')}")
    print(f"Letters correct: {100 * accuracy(r.get('plaintext', ''), p):.1f}%  | "
          f"candidates scored {r['evaluations']}  | time {1000 * r['time']:.0f} ms")
    print(f"First 80 letters: {r.get('plaintext', '')[:80]}")


if __name__ == "__main__":
    main()
