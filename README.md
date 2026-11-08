# VH-Cascade Cipher — Design and Break a Custom Classical Cipher

**CT-486 Network and Information Security — Complex Computing Problem (CLO3)**
NED University of Engineering & Technology · Final Year Cyber Security · Batch 2023

| Member | Roll No. |
|---|---|
| Syed Muneeb Ali Shah | CR-23012 |
| Muneeb Ahmed | CR-23021 |
| S.M. Faizan Hyder | CR-23026 |
| Kabeer Ahmed | CR-23034 |

## The cipher

A two-stage product cipher over A–Z:

1. **Stage 1 – Vigenère:** `V_i = (P_i + K_(i mod m)) mod 26`, keyword length `m ≥ 10`
2. **Stage 2 – Hill (2×2):** `[C_2t, C_2t+1] = H · [V_2t, V_2t+1] mod 26`, `H` from a 4-letter key, `gcd(det H, 26) = 1`

Decryption applies `H⁻¹` first, then subtracts the Vigenère key. Default key: `CYBERSECURITY` + `HILL`.

## Files

| File | Purpose |
|---|---|
| `cipher.py` | Encryption / decryption (and the Shift cipher baseline) |
| `attacks.py` | Known-plaintext attack, ciphertext-only frequency-analysis attack, Shift brute force |
| `main.py` | Demo: encrypt, decrypt, then break the cipher both ways |
| `experiments.py` | Success-rate, effort and timing experiments → `results/results.json` |
| `make_charts.py` | Figures for the report → `results/*.png` |
| `data/sample_plaintext.txt` | Public-domain English text (G. K. Chesterton, *The Man Who Was Thursday*, Project Gutenberg) used as test plaintext |

## Run

```bash
pip install numpy matplotlib
python main.py                                   # demo
python cipher.py enc "attack at dawn" --vkey CYBERSECURITY --hkey HILL
python cipher.py dec "<ciphertext>"  --vkey CYBERSECURITY --hkey HILL
python experiments.py && python make_charts.py   # reproduce the report numbers (~4 min)
```

Input handling: letters are upper-cased, anything outside A–Z is removed, and odd-length messages are padded with `X`.
