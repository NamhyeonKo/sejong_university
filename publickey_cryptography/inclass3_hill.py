#   hill cipher
import numpy as np
from math import gcd

#   change num to char or char to num
def char_to_num(c):
    return ord(c.upper()) - ord('A')
def num_to_char(n):
    return chr(n % 26 + ord('A'))

def key_to_matrix(key, n):
    key_nums = [char_to_num(k) for k in key.upper()]
    #   make N x N matrix
    return np.array(key_nums).reshape(n, n)

def mod_inverse(a, mod):
    for i in range(1, mod):
        if (a*i) % mod == 1:
            return i

def make_inverse_matrix(matrix):
    det_inv = mod_inverse(np.linalg.det(matrix))
    matrix_adj = matrix.T

    

    return

n = 3
key = 'rrfvsvcct'
plaintext = 'paymoremoney'

key_matrix = key_to_matrix(key, n)
print(key_matrix)
matrix_inv = make_inverse_matrix(key_matrix)
print(matrix_inv)


#! example
#? 3
#? RRFVSVCCT
#? paymoremoney