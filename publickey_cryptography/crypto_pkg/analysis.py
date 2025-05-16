# crypto_pkg/analysis.py
from collections import Counter
from .shift_cipher import shift_cipher

def brute_force_shift(ciphertext: str, decrypt: bool=False) -> str:
    return "\n".join(
        f"Shift {s}: {shift_cipher(ciphertext, s, decrypt)}"
        for s in range(26)
    )

def frequency_analysis(ciphertext: str, decrypt: bool=False) -> str:
    common = "etaoinshrdlcumwfgypbvkjxqz"
    cnts = Counter(ch for ch in ciphertext.lower() if ch.isalpha())
    if not cnts:
        return ""
    most = cnts.most_common(1)[0][0]
    shifts = [(ord(most)-ord(c)) for c in common]
    return "\n".join(
        f"Shift {s}: {shift_cipher(ciphertext, s, decrypt)}"
        for s in shifts
    )