import tkinter as tk
from tkinter import ttk
import string
from collections import Counter

#   Shift Cipher encrypto & decrypto
def shift_cipher(text, shift, decrypt=False):
    #   decrypto is reverse encrypto!
    if decrypt:
        shift = -shift
    result = ""
    for char in text:
        #   check letter is alphabet, otherwise do not change letter
        if char.isalpha():
            #   determine capital letter and small letter
            #   shift base is an Ascii code of basic character
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

#   function to input letters in board
def input_in_board(letters, board):
    #   nput playfair key in board but once in a while
    for l in letters:
        if l == 'j':  # replace 'j' with 'i'
            l = 'i'
        if l not in board:
            board.append(l)

#   function to make playfair key board
def make_playfair_key_board(playfair_key):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    board = []

    input_in_board(playfair_key, board)
    input_in_board(alphabet, board)

    return board

#   function to preprocess plain text for Playfair cipher
def preprocess_text(plain_text):
    result = []
    i = 0
    while i < len(plain_text):
        a = plain_text[i]
        b = plain_text[i + 1] if i + 1 < len(plain_text) else 'x'

        #   when the pair letters are the same, put an 'x' between
        if a == b:
            result.append(a)
            result.append('x')
        else:
            result.append(a)
            result.append(b)
            i += 1
        i += 1

    #   when last letter pair is odd, put an 'x' at the end
    if len(result) % 2 == 1:
        result.append('x')

    return "".join(result)

#   function to get position of a character in the board
def get_position(board, char):
    idx = board.index(char)
    return idx // 5, idx % 5  # row, column

#   function to encrypt plain text using playfair cipher
def playfair_cipher(plain_text, key, encrypt=True):
    board = make_playfair_key_board(key)
    text = preprocess_text(plain_text)
    result = []

    #   decryption, reverse the direction of character movement.
    shift = 1 if encrypt else -1

    for i in range(0, len(text), 2):
        a_x, a_y = get_position(board, text[i])
        b_x, b_y = get_position(board, text[i + 1])

        #   if both of the pair letters are the same row, move one space to the right side
        if a_x == b_x:
            result.append(board[a_x * 5 + (a_y + shift) % 5])
            result.append(board[b_x * 5 + (b_y + shift) % 5])
        #   if both of the pair letters are the same column, move one space down
        elif a_y == b_y:
            result.append(board[((a_x + shift) % 5) * 5 + a_y])
            result.append(board[((b_x + shift) % 5) * 5 + b_y])
        #   if both of the pair letters make rectangle, column switch not move row
        else:
            result.append(board[a_x * 5 + b_y])
            result.append(board[b_x * 5 + a_y])

    result_text = "".join(result)
    if not encrypt:
        result_text = result_text.replace("x","")

    return result_text

#   Brute Force Attack (Shift Cipher)
def brute_force_shift(ciphertext, encrypt):
    return "\n".join(f"Shift {shift}: {shift_cipher(ciphertext, shift, decrypt=encrypt)}" for shift in range(26))

#   Frequency Analysis Attack (Shift Cipher)
def frequency_analysis(ciphertext, encrypt):
    #   high-frequency letters in English
    common_letters = "etaoinshrdlcumwfgypbvkjxqz"
    #   find high-frequency characters in ciphertext
    letter_counts = Counter(filter(str.isalpha, ciphertext.lower()))
    most_common = [x[0] for x in letter_counts.most_common()]
    #   set shift with frequency
    possible_shifts = [ord(most_common[0]) - ord(c) for c in common_letters]
    return "\n".join(f"Shift {s}: {shift_cipher(ciphertext, s, decrypt=encrypt)}" for s in possible_shifts)

# GUI
root = tk.Tk()
root.title("encrypto/decrypto program")
root.geometry("500x1000")

frame = ttk.Frame(root, padding=20)
frame.pack(expand=True, fill="both")

cipher_var = tk.StringVar(value="Playfair")
ttk.Label(frame, text="choosing method of encryption:").pack()
ttk.Combobox(frame, textvariable=cipher_var, values=["Playfair", "Shift Brute Force", "Shift Frequency"]).pack()

ttk.Label(frame, text="input text:").pack()
text_entry = ttk.Entry(frame, width=50)
text_entry.pack()

ttk.Label(frame, text="input key (Only playfair):").pack()
key_entry = ttk.Entry(frame, width=50)
key_entry.pack()

#   Encryption and Decryption Processing Functions
def encrypt_text():
    execute(encrypt=True)
def decrypt_text():
    execute(encrypt=False)

def execute(encrypt=False):
    text = text_entry.get()
    key = key_entry.get()
    cipher_type = cipher_var.get()
    
    if cipher_type == "Playfair":
        result = playfair_cipher(text, key, encrypt)
    elif cipher_type == "Shift Brute Force":
        result = brute_force_shift(text, encrypt)
    elif cipher_type == "Shift Frequency":
        result = frequency_analysis(text, encrypt)
    else:
        result = "wrong choice"
    
    result_text.set(f"result:\n {result}")

#   making encrypto & decrypto buttons
button_frame = ttk.Frame(frame)
button_frame.pack(pady=10)
#   choose button and work each case
ttk.Button(button_frame, text="encrypto", command=encrypt_text).pack(side="left", padx=10)
ttk.Button(button_frame, text="decrypto", command=decrypt_text).pack(side="left", padx=10)
result_text = tk.StringVar(value="result")
ttk.Label(frame, textvariable=result_text, wraplength=450).pack()

root.mainloop()