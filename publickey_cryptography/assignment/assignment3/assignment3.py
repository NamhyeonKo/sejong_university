import numpy as np
import tkinter as tk
from tkinter import ttk
import random

#   Change num to char or char to num
def char_to_num(c):
    return ord(c.upper()) - ord('A')
def num_to_char(n):
    return chr(n % 26 + ord('A'))

#   Make key to N x N matrix
def key_to_matrix(key, n):
    key_nums = [char_to_num(k) for k in key.upper()]
    return np.array(key_nums).reshape(n, n)

#   Divide the plain text into n characters
def text_to_blocks(text, n):
    nums = [char_to_num(c) for c in text.upper().replace(" ", "")]
    if len(nums) % n != 0:
        nums += [char_to_num('X')] * (n - len(nums) % n)
    return [nums[i:i+n] for i in range(0, len(nums), n)]

def minor(matrix, row, col):
    return np.delete(np.delete(matrix, row, axis=0), col, axis=1)

#   Make determinant wit mod (I used it with mod 26)
def determinant_mod(matrix, mod):
    matrix = np.array(matrix)
    n = matrix.shape[0]

    if n != matrix.shape[1]:
        raise ValueError("Matrix Error")
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

#   For making adj_matrix
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

#   Make inverse matrix with det and adj
def make_inverse_matrix(matrix):
    det = determinant_mod(matrix,26)
    det_inv = mod_inverse(det,26)
    cof_matrix = cofactor_matrix(matrix,26)
    adj_matrix = cof_matrix.T % 26
    return (adj_matrix * det_inv) % 26

#   This is real hill algoritm when we use in hill encrypt or decrypt
def hill_algorithm(plaintext, key_matrix):
    n = key_matrix.shape[0]
    blocks = text_to_blocks(plaintext, n)
    result = ""
    for block in blocks:
        vec = np.array(block).reshape((1, n))
        enc = np.dot(vec, key_matrix) % 26
        result += ''.join(num_to_char(int(i)) for i in enc.flatten())
    return result

#   Make random key use inputed n
def generate_random_key(n):
    while True:
        key_nums = [random.randint(0, 25) for _ in range(n * n)]
        matrix = np.array(key_nums).reshape(n, n)
        try:
            _ = make_inverse_matrix(matrix)
            return matrix
        except:
            continue

#   GUI
root = tk.Tk()
root.title("Hill Cipher GUI")
root.geometry("600x600")

frame = ttk.Frame(root, padding=20)
frame.pack(expand=True, fill="both")

n_var = tk.StringVar()
key_var = tk.StringVar()
input_var = tk.StringVar()
result_var = tk.StringVar(value="Result will be shown here")
generated_key_var = tk.StringVar()

ttk.Label(frame, text="Matrix size n:").pack()
ttk.Entry(frame, textvariable=n_var).pack()

ttk.Label(frame, text="Key (length n^2) or generate random key below:").pack()
ttk.Entry(frame, textvariable=key_var).pack()

#   Make random key
def generate_key():
    try:
        n = int(n_var.get())
        matrix = generate_random_key(n)
        key_chars = ''.join(num_to_char(num) for num in matrix.flatten())
        key_var.set(key_chars)

        #   Show N x N key with numbers
        display = "Generated Key Matrix ({}x{}):\n".format(n, n)
        for row in matrix:
            display += ' '.join(f"{int(c):2}" for c in row) + "\n"
        generated_key_var.set(display)

    except Exception as e:
        generated_key_var.set(f"Error: {e}")

#   button to generate random key
key_button = ttk.Button(frame, text="Generate Random Key", command=generate_key)
key_button.pack(pady=5)

ttk.Label(frame, textvariable=generated_key_var, justify="left").pack()

ttk.Label(frame, text="Input Text:").pack()
ttk.Entry(frame, textvariable=input_var).pack()

def run(mode):
    try:
        n = int(n_var.get())
        key = key_var.get()
        text = input_var.get()
        key_matrix = key_to_matrix(key, n)
        if mode == "encrypt":
            result = hill_algorithm(text, key_matrix)
        else:
            inv = make_inverse_matrix(key_matrix)
            result = hill_algorithm(text, inv)
        result_var.set(f"Result: {result}")
    except Exception as e:
        result_var.set(f"Error: {e}")

button_frame = ttk.Frame(frame)
button_frame.pack(pady=10)

ttk.Button(button_frame, text="Encrypt", command=lambda: run("encrypt")).pack(side="left", padx=10)
ttk.Button(button_frame, text="Decrypt", command=lambda: run("decrypt")).pack(side="left", padx=10)

ttk.Label(frame, textvariable=result_var, wraplength=450).pack(pady=20)

root.mainloop()
