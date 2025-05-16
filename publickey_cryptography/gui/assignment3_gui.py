import tkinter as tk
from tkinter import ttk
from crypto_pkg.hill import (
    key_to_matrix,
    generate_random_key,
    hill_encrypt,
    hill_decrypt,
    num_to_char
)

class CryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Assignment 3: Hill Cipher")
        self.geometry("600x600")
        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=20)
        frm.pack(expand=True, fill="both")

        # ─── N 입력 ───
        ttk.Label(frm, text="Matrix size (n):").pack(anchor="w")
        self.n_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.n_var).pack(fill="x")

        # ─── 키 입력 ───
        ttk.Label(frm, text="Key (length n²) or Generate Random:").pack(anchor="w")
        self.key_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.key_var).pack(fill="x")
        ttk.Button(frm, text="Generate Random Key", command=self._on_generate_key).pack(pady=5)
        self.generated_label = ttk.Label(frm, text="", justify="left")
        self.generated_label.pack(fill="x")

        # ─── 평문/암호문 입력 ───
        ttk.Label(frm, text="Input Text:").pack(anchor="w")
        self.input_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.input_var).pack(fill="x")

        # ─── 실행 버튼 ───
        btn_fr = ttk.Frame(frm); btn_fr.pack(pady=10)
        ttk.Button(btn_fr, text="Encrypt", command=lambda: self._run("encrypt")).pack(side="left", padx=10)
        ttk.Button(btn_fr, text="Decrypt", command=lambda: self._run("decrypt")).pack(side="left", padx=10)

        # ─── 결과 표시 ───
        self.result_var = tk.StringVar(value="Result will appear here")
        ttk.Label(frm, textvariable=self.result_var, wraplength=550, justify="left").pack(pady=20)

    def _on_generate_key(self):
        try:
            n = int(self.n_var.get())
            mat = generate_random_key(n)
            # 키 문자열 및 매트릭스 표시
            key_str = "".join(num_to_char(x) for x in mat.flatten())
            self.key_var.set(key_str)
            disp = f"Generated {n}×{n} Key:\n" + "\n".join(" ".join(f"{int(x):2}" for x in row) for row in mat)
            self.generated_label.config(text=disp)
        except Exception as e:
            self.generated_label.config(text=f"Error: {e}")

    def _run(self, mode: str):
        try:
            n = int(self.n_var.get())
            key_str = self.key_var.get()
            text   = self.input_var.get()
            mat    = key_to_matrix(key_str, n)
            if mode == "encrypt":
                res = hill_encrypt(text, mat)
            else:
                res = hill_decrypt(text, mat)
            self.result_var.set(res)
        except Exception as e:
            self.result_var.set(f"Error: {e}")