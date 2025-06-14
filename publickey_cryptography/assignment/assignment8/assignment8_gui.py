import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from rsa import generate_rsa_keys, rsa_encrypt, rsa_decrypt

class RsaGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("RSA Cryptosystem Simulator (최종 수정본)")
        self.master.geometry("750x650")

        self.public_key = None
        self.private_key = None
        self.p, self.q = None, None
        self.ciphertext = None

        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_widgets(main_frame)

    def _create_widgets(self, parent):
        # 1. 키 생성
        key_frame = ttk.LabelFrame(parent, text="1. Key Generation", padding="10")
        key_frame.pack(fill=tk.X, expand=True, pady=5)

        ttk.Label(key_frame, text="Key Size (bits for p, q):").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.key_size_var = tk.StringVar(value="128")
        ttk.Combobox(key_frame, textvariable=self.key_size_var, values=["64", "128", "256", "512"], state="readonly").grid(row=0, column=1, sticky=tk.EW)
        
        ttk.Button(key_frame, text="Generate RSA Keys", command=self.generate_keys).grid(row=1, column=0, columnspan=2, pady=5)
        
        self.key_display = scrolledtext.ScrolledText(key_frame, height=10, wrap=tk.WORD, state='disabled')
        self.key_display.grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=5)
        key_frame.columnconfigure(1, weight=1)

        # 2. 암호화
        enc_frame = ttk.LabelFrame(parent, text="2. Encryption", padding="10")
        enc_frame.pack(fill=tk.X, expand=True, pady=5)
        ttk.Label(enc_frame, text="Plaintext:").grid(row=0, column=0, sticky=tk.W)
        self.plaintext_var = tk.StringVar(value="")
        ttk.Entry(enc_frame, textvariable=self.plaintext_var).grid(row=0, column=1, sticky=tk.EW)
        ttk.Button(enc_frame, text="Encrypt", command=self.encrypt_message).grid(row=1, column=0, columnspan=2, pady=5)
        ttk.Label(enc_frame, text="Ciphertext (Integer):").grid(row=2, column=0, sticky=tk.W)
        self.ciphertext_var = tk.StringVar(value="N/A")
        ttk.Label(enc_frame, textvariable=self.ciphertext_var, wraplength=500, foreground="red").grid(row=2, column=1, sticky=tk.W)
        enc_frame.columnconfigure(1, weight=1)
        
        # 3. 복호화
        dec_frame = ttk.LabelFrame(parent, text="3. Decryption", padding="10")
        dec_frame.pack(fill=tk.X, expand=True, pady=5)
        ttk.Button(dec_frame, text="Decrypt", command=self.decrypt_message).pack(pady=5)
        ttk.Label(dec_frame, text="Decrypted Plaintext:").pack()
        self.decrypted_var = tk.StringVar(value="N/A")
        ttk.Label(dec_frame, textvariable=self.decrypted_var, foreground="blue", font=('Helvetica', 10, 'bold')).pack()

    def _display_keys(self):
        self.key_display.config(state='normal')
        self.key_display.delete('1.0', tk.END)
        if self.public_key and self.private_key:
            e, n = self.public_key
            d, _ = self.private_key
            text_to_display = (f"Generated Primes (p, q):\n p = {self.p}\n q = {self.q}\n\n"
                               f"Public Key (e, n):\n e = {e}\n n = {n}\n\n"
                               f"Private Key (d, n):\n d = {d}\n n = {n}")
            self.key_display.insert('1.0', text_to_display)
        self.key_display.config(state='disabled')
        
    def generate_keys(self):
        try:
            bits = int(self.key_size_var.get())
            self.public_key, self.private_key, self.p, self.q = generate_rsa_keys(bits)
            self._display_keys()
            messagebox.showinfo("Success", "RSA keys generated successfully.")
            self.ciphertext_var.set("N/A")
            self.decrypted_var.set("N/A")
            self.ciphertext = None
        except (ValueError, RuntimeError) as e:
            messagebox.showerror("Key Generation Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {e}")

    def encrypt_message(self):
        if not self.public_key:
            messagebox.showwarning("Warning", "Please generate keys first.")
            return
        plaintext = self.plaintext_var.get()
        if not plaintext:
            messagebox.showwarning("Warning", "Plaintext cannot be empty.")
            return
        try:
            self.ciphertext = rsa_encrypt(self.public_key, plaintext)
            self.ciphertext_var.set(str(self.ciphertext))
            self.decrypted_var.set("N/A")
        except ValueError as e:
            messagebox.showerror("Encryption Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")

    def decrypt_message(self):
        if not self.private_key or self.ciphertext is None:
            messagebox.showwarning("Warning", "Please encrypt a message first.")
            return
        try:
            decrypted_text = rsa_decrypt(self.private_key, self.ciphertext)
            self.decrypted_var.set(decrypted_text)
        except ValueError as e:
            messagebox.showerror("Decryption Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred during decryption: {e}")