import tkinter as tk
from tkinter import ttk

from crypto_pkg.playfair       import playfair_cipher
from crypto_pkg.analysis       import brute_force_shift, frequency_analysis

class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Assignment 2: Cipher Analysis")
        self.geometry("500x1000")
        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=20)
        frm.pack(expand=True, fill="both")

        self.cipher_var = tk.StringVar(value="Playfair")
        ttk.Label(frm, text="Choose method:").pack()
        ttk.Combobox(frm, textvariable=self.cipher_var,
                     values=["Playfair","Shift Brute Force","Shift Frequency"]
        ).pack()

        ttk.Label(frm, text="Input text:").pack()
        self.text_entry = ttk.Entry(frm, width=50); self.text_entry.pack()

        ttk.Label(frm, text="Key (Playfair only):").pack()
        self.key_entry  = ttk.Entry(frm, width=50); self.key_entry.pack()

        btn_fr = ttk.Frame(frm); btn_fr.pack(pady=10)
        ttk.Button(btn_fr, text="Encrypt", command=lambda: self._execute(True)
        ).pack(side="left", padx=10)
        ttk.Button(btn_fr, text="Decrypt", command=lambda: self._execute(False)
        ).pack(side="left", padx=10)

        self.result_text = tk.StringVar(value="Result will appear here")
        ttk.Label(frm, textvariable=self.result_text, wraplength=450).pack()

    def _execute(self, encrypt: bool):
        txt = self.text_entry.get()
        key = self.key_entry.get()
        choice = self.cipher_var.get()

        if choice == "Playfair":
            out = playfair_cipher(txt, key, encrypt)
        elif choice == "Shift Brute Force":
            out = brute_force_shift(txt, decrypt=not encrypt)
        elif choice == "Shift Frequency":
            out = frequency_analysis(txt, decrypt=not encrypt)
        else:
            out = "Invalid choice"
        self.result_text.set(out)