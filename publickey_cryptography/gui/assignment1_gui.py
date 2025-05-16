import tkinter as tk
from tkinter import ttk

from crypto_pkg.shift_cipher import shift_cipher
from crypto_pkg.substitution_cipher import substitution_cipher, generate_random_key
from crypto_pkg.vigenere_cipher import vigenere_cipher

class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Crypto GUI")
        self.geometry("500x400")

        self.cipher_var = tk.StringVar(value="Shift")
        self.result_text = tk.StringVar()
        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=20)
        frm.pack(expand=True, fill="both")

        ttk.Label(frm, text="Select Cipher:").pack()
        cb = ttk.Combobox(frm, textvariable=self.cipher_var,
                          values=["Shift","Substitution","Vigenere"])
        cb.pack()
        cb.bind("<<ComboboxSelected>>", self._on_type_change)

        ttk.Label(frm, text="Input text:").pack()
        self.text_entry = ttk.Entry(frm, width=50); self.text_entry.pack()

        ttk.Label(frm, text="Input key:").pack()
        self.key_entry = ttk.Entry(frm, width=50); self.key_entry.pack()

        btn_fr = ttk.Frame(frm); btn_fr.pack(pady=10)
        ttk.Button(btn_fr, text="Encrypt", command=self.encrypt).pack(side="left", padx=5)
        ttk.Button(btn_fr, text="Decrypt", command=self.decrypt).pack(side="left", padx=5)

        ttk.Label(frm, textvariable=self.result_text, wraplength=450).pack()

    def _on_type_change(self, _):
        if self.cipher_var.get() == "Substitution":
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, generate_random_key())

    def process(self, encrypt: bool):
        text = self.text_entry.get()
        key  = self.key_entry.get()
        typ  = self.cipher_var.get()
        try:
            if typ == "Shift":
                if not key.isdigit(): raise ValueError("숫자만 입력!")
                res = shift_cipher(text, int(key), decrypt=not encrypt)
            elif typ == "Substitution":
                if len(key)!=26 or not key.isalpha(): raise ValueError("26글자 알파벳 키!")
                res = substitution_cipher(text, key, decrypt=not encrypt)
            else:  # Vigenere
                if not key.isalpha(): raise ValueError("알파벳만 입력!")
                res = vigenere_cipher(text, key, decrypt=not encrypt)
        except ValueError as e:
            self.result_text.set(str(e))
        else:
            self.result_text.set(f"Result: {res}")

    def encrypt(self):
        self.process(encrypt=True)

    def decrypt(self):
        self.process(encrypt=False)