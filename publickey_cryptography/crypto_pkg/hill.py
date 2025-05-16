# crypto_pkg/hill.py
import numpy as np
import random
from typing import List, Tuple

# ────────── 문자 ↔ 숫자 ──────────
def char_to_num(c: str) -> int:
    return ord(c.upper()) - ord('A')

def num_to_char(n: int) -> str:
    return chr(n % 26 + ord('A'))

# ────────── 키 매트릭스 생성 ──────────
def key_to_matrix(key: str, n: int) -> np.ndarray:
    nums = [char_to_num(c) for c in key.upper()]
    return np.array(nums).reshape(n, n)

# ────────── 평문을 블록으로 분할 ──────────
def text_to_blocks(text: str, n: int) -> List[List[int]]:
    nums = [char_to_num(c) for c in text.upper() if c.isalpha()]
    if len(nums) % n != 0:
        nums += [char_to_num('X')] * (n - len(nums) % n)
    return [nums[i:i+n] for i in range(0, len(nums), n)]

# ────────── 행렬식, 여인자(코팩터), 역원 계산 ──────────
def minor(matrix: np.ndarray, row: int, col: int) -> np.ndarray:
    return np.delete(np.delete(matrix, row, axis=0), col, axis=1)

def determinant_mod(matrix: np.ndarray, mod: int = 26) -> int:
    m = np.array(matrix)
    n = m.shape[0]
    if n != m.shape[1]:
        raise ValueError("Matrix must be square")
    if n == 1:
        return int(m[0,0] % mod)
    if n == 2:
        a,b = m[0]; c,d = m[1]
        return int((a*d - b*c) % mod)
    det = 0
    for j in range(n):
        det += ((-1)**j) * m[0,j] * determinant_mod(minor(m,0,j),mod)
    return int(det % mod)

def cofactor_matrix(matrix: np.ndarray, mod: int = 26) -> np.ndarray:
    n = matrix.shape[0]
    cof = np.zeros_like(matrix, dtype=int)
    for i in range(n):
        for j in range(n):
            cof[i,j] = ((-1)**(i+j) * determinant_mod(minor(matrix,i,j),mod)) % mod
    return cof

def mod_inverse(a: int, mod: int = 26) -> int:
    a %= mod
    for x in range(1,mod):
        if (a*x) % mod == 1:
            return x
    raise ValueError(f"No modular inverse for {a} mod {mod}")

def make_inverse_matrix(matrix: np.ndarray) -> np.ndarray:
    det = determinant_mod(matrix)
    inv_det = mod_inverse(det)
    adj = cofactor_matrix(matrix).T % 26
    return (adj * inv_det) % 26

# ────────── Hill 알고리즘 ──────────
def hill_encrypt(plaintext: str, key_matrix: np.ndarray) -> str:
    n = key_matrix.shape[0]
    blocks = text_to_blocks(plaintext, n)
    out = ""
    for blk in blocks:
        vec = np.array(blk).reshape(1,n)
        enc = (vec @ key_matrix) % 26
        out += "".join(num_to_char(int(x)) for x in enc.flatten())
    return out

def hill_decrypt(ciphertext: str, key_matrix: np.ndarray) -> str:
    inv = make_inverse_matrix(key_matrix)
    return hill_encrypt(ciphertext, inv)

# ────────── 랜덤 키 생성 ──────────
def generate_random_key(n: int) -> np.ndarray:
    while True:
        mat = np.random.randint(0,26,(n,n))
        try:
            _ = make_inverse_matrix(mat)
            return mat
        except ValueError:
            continue