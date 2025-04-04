import tkinter as tk
from tkinter import ttk
import string
import random

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

#   Substitution Cipher encrypto & decrypto
#   It could not be made into upper and lowercase cases, so it was unified into lowercase and printed out.
def substitution_cipher(text, key, decrypt=False):
    #   making lower alphabet character list
    alphabet = string.ascii_lowercase
    #   grouping alphabet list and random key accordingly and matching each letter
    key_map = dict(zip(alphabet, key.lower())) if not decrypt else dict(zip(key.lower(), alphabet))
    return "".join(key_map.get(char, char) for char in text.lower())

#   Vigenere Cipher encrypto & decrypto
def vigenere_cipher(text, key, decrypt=False):
    result = []
    key = key.lower()
    key_len = len(key)
    #   using key_index to start key's first letter when new word starts
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % key_len]) - ord('a')
            shift = -shift if decrypt else shift

            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        
            key_index += 1
        else:
            result.append(char)
            if char == " ":
                key_index = 0
    
    return "".join(result)

#   Encryption and Decryption Processing Functions
def encrypt_text():
    process_text(encrypt=True)

def decrypt_text():
    process_text(encrypt=False)

def process_text(encrypt=True):
    text = text_entry.get()
    key = key_entry.get()
    cipher_type = cipher_var.get()
    decrypt = not encrypt  #    case of encrypto is True or False

    result = "choose any cipher"  # setting a initial result

    #   Shift Cipher
    if cipher_type == "Shift":
        if not key.isdigit():
            result_text.set("Please input only numbers for key!")
            return
        shift = int(key)
        result = shift_cipher(text, shift, decrypt)

    #   Substitution Cipher
    elif cipher_type == "Substitution":
        if len(key) != 26 or not key.isalpha():
            result_text.set("Please input 26 letters of alphabet randomly for key!")
            return
        result = substitution_cipher(text, key, decrypt)

    #   Vigenere Cipher
    elif cipher_type == "Vigenere":
        if not key.isalpha():
            result_text.set("Please input only alphabets for key!")
            return
        result = vigenere_cipher(text, key, decrypt)

    #   setting result text's form
    result_text.set(f"result : {result}")

#   making new random key when user choose substitution cipher
def generate_random_key():
    random_key = list(string.ascii_lowercase)
    random.shuffle(random_key)
    return ''.join(random_key)

#   function when change method of encrypto or decrypto
def on_cipher_type_change(event):
    #   if method is substitution, we show random key 
    if cipher_var.get() == "Substitution":
        #   rewrite existing key with new random key
        key_entry.delete(0, tk.END)  #  delete existing key
        key_entry.insert(0, generate_random_key())  #   write new random key


# Tkinter GUI settings
root = tk.Tk()
root.title("encrypto/decrypto program")
root.geometry("500x400")

frame = ttk.Frame(root, padding=20)
frame.pack(expand=True, fill="both")

#   Select Encrypto Method
cipher_var = tk.StringVar(value="Shift")
ttk.Label(frame, text="Select Encrypto Method:").pack()
cipher_combobox = ttk.Combobox(frame, textvariable=cipher_var, values=["Shift", "Substitution", "Vigenere"])
cipher_combobox.pack()
cipher_combobox.bind("<<ComboboxSelected>>", on_cipher_type_change)  #  Register an event handler when selected

#   making a label to input plain or cipher text
#   When the encryption button is pressed, plain text, and when the decryption button is pressed, cipher text
ttk.Label(frame, text="input text :").pack()
text_entry = ttk.Entry(frame, width=50)
text_entry.pack()

#   making a label to input keys
ttk.Label(frame, text="input key :").pack()
key_entry = ttk.Entry(frame, width=50)
key_entry.pack()

#   making encrypto & decrypto buttons
button_frame = ttk.Frame(frame)
button_frame.pack(pady=10)

#   choose button and work each case
ttk.Button(button_frame, text="encrypto", command=encrypt_text).pack(side="left", padx=10)
ttk.Button(button_frame, text="decrypto", command=decrypt_text).pack(side="left", padx=10)

#   show a result
result_text = tk.StringVar()
ttk.Label(frame, textvariable=result_text, wraplength=450).pack()

root.mainloop()