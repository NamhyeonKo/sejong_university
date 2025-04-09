#   Hill cipher
import numpy as np
from math import gcd

#   Change num to char or char to num
def char_to_num(c):
    return ord(c.upper()) - ord('A')
def num_to_char(n):
    return chr(n % 26 + ord('A'))

def key_to_matrix(key, n):
    key_nums = [char_to_num(k) for k in key.upper()]
    #   make N x N matrix
    return np.array(key_nums).reshape(n, n)

#   Divide the plain text into n characters
def text_to_blocks(text, n):
    nums = [char_to_num(c) for c in text.upper().replace(" ", "")]
    if len(nums) % n != 0:
        nums += [char_to_num('X')] * (n - len(nums) % n)
    return [nums[i:i+n] for i in range(0, len(nums), n)]

def minor(matrix, row, col):
    # i행 j열 제거한 소행렬 리턴
    return np.delete(np.delete(matrix, row, axis=0), col, axis=1)

def determinant_mod(matrix, mod):
    matrix = np.array(matrix)
    n = matrix.shape[0]
    
    if n != matrix.shape[1]:
        raise ValueError("정방행렬만 가능합니다.")
    if n == 1:
        return matrix[0, 0] % mod
    elif n == 2:
        a, b = matrix[0]
        c, d = matrix[1]
        return (a * d - b * c) % mod
    det = 0
    for j in range(n):
        cofactor = ((-1) ** j) * matrix[0][j] * determinant_mod(minor(matrix, 0, j), mod)
        det += cofactor

    return det % mod

def cofactor_matrix(matrix, mod=26):
    n = matrix.shape[0]
    cof = np.zeros_like(matrix, dtype=int)
    for i in range(n):
        for j in range(n):
            submatrix = minor(matrix, i, j)
            minor_det = determinant_mod(submatrix, mod)
            cof[i][j] = ((-1) ** (i + j)) * minor_det % mod
    return cof % mod

def mod_inverse(a, mod):
    for i in range(1, mod):
        if (a * i) % mod == 1:
            return i
    raise ValueError(f"{a}의 mod {mod}에서 역원이 존재하지 않습니다.")

def make_inverse_matrix(matrix):
    det = determinant_mod(matrix,26)
    det_inv = mod_inverse(det,26)

    cof_matrix = cofactor_matrix(matrix,26)
    adj_matrix = cof_matrix.T % 26

    return (adj_matrix * det_inv) % 26

#   Encryption and decryption
def hill_algorithm(plaintext, key_matrix):
    n = key_matrix.shape[0]
    blocks = text_to_blocks(plaintext, n)
    result = ""
    for block in blocks:
        vec = np.array(block).reshape((1, n))
        enc = np.dot(vec, key_matrix) % 26
        result += ''.join(num_to_char(int(i)) for i in enc.flatten())
    return result

n = int(input("n : "))
key = input("key : ")
plaintext = input("plaint text : ")

key_matrix = key_to_matrix(key, n)
key_matrix_inv = make_inverse_matrix(key_matrix)
cipher_text = hill_algorithm(plaintext, key_matrix)

print(cipher_text)
print(hill_algorithm(cipher_text, key_matrix_inv))

#! example
#? 3
#? RRFVSVCCT
#? paymoremoney