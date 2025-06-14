# assignment6_gui.py
import tkinter as tk
from tkinter import ttk, messagebox

# crypto_pkg 패키지에서 필요한 함수들을 가져옵니다.
from diffie_hellman import generate_dh_params, generate_person_keys, generate_shared_secret
from shift_cipher import shift_cipher

class Assignment6GUI:
    """
    Diffie-Hellman 키 교환 프로토콜 시뮬레이션을 위한 GUI 클래스.
    """
    def __init__(self, master):
        self.master = master
        master.title("Assignment 6: Diffie-Hellman Key Exchange")
        master.geometry("950x750")

        # 변수 초기화
        self.p, self.g = None, None
        self.xa, self.ya = None, None # Alice, Bob 개인키
        self.A, self.B = None, None   # Alice, Bob 공개키
        self.s_alice, self.s_bob = None, None # 공유 비밀키
        self.ciphertext = None
        
        # GUI 위젯 생성
        self._create_widgets()

    def _create_widgets(self):
        # 1. 파라미터 생성 (p, g)
        param_frame = ttk.LabelFrame(self.master, text="[Part 1] Step 1: Generate Global Parameters")
        param_frame.pack(padx=10, pady=10, fill="x")

        ttk.Label(param_frame, text="Select Key Size (bits):").pack(side=tk.LEFT, padx=5, pady=5)
        self.key_size_var = tk.StringVar(value='128')
        key_size_options = ['16', '32', '64', '128', '256', '512', '1024', '2048']
        key_size_menu = ttk.OptionMenu(param_frame, self.key_size_var, key_size_options[3], *key_size_options)
        key_size_menu.pack(side=tk.LEFT, padx=5, pady=5)

        ttk.Button(param_frame, text="Generate p and g", command=self.run_generate_params).pack(side=tk.LEFT, padx=5, pady=5)
        self.p_g_label = ttk.Label(param_frame, text="p and g not generated.", foreground="red")
        self.p_g_label.pack(side=tk.LEFT, padx=10)

        # 2. 키 교환 과정 (Alice & Bob)
        exchange_frame = ttk.LabelFrame(self.master, text="[Part 1] Step 2: Key Exchange")
        exchange_frame.pack(padx=10, pady=10, fill="x")

        alice_frame = ttk.LabelFrame(exchange_frame, text="Alice's Side")
        alice_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")
        bob_frame = ttk.LabelFrame(exchange_frame, text="Bob's Side")
        bob_frame.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")
        exchange_frame.grid_columnconfigure(0, weight=1)
        exchange_frame.grid_columnconfigure(1, weight=1)

        # Alice 위젯
        ttk.Button(alice_frame, text="Generate Alice's Keys", command=self.run_alice_keys).pack(pady=5, fill='x')
        self.alice_priv_label = ttk.Label(alice_frame, text="Private (xa): ?")
        self.alice_priv_label.pack(pady=3, anchor='w')
        self.alice_pub_label = ttk.Label(alice_frame, text="Public (A): ?")
        self.alice_pub_label.pack(pady=3, anchor='w')
        ttk.Button(alice_frame, text="Calculate Shared Secret", command=self.run_alice_secret).pack(pady=5, fill='x')
        self.alice_secret_label = ttk.Label(alice_frame, text="Shared Secret (s): ?")
        self.alice_secret_label.pack(pady=3, anchor='w')

        # Bob 위젯
        ttk.Button(bob_frame, text="Generate Bob's Keys", command=self.run_bob_keys).pack(pady=5, fill='x')
        self.bob_priv_label = ttk.Label(bob_frame, text="Private (yb): ?")
        self.bob_priv_label.pack(pady=3, anchor='w')
        self.bob_pub_label = ttk.Label(bob_frame, text="Public (B): ?")
        self.bob_pub_label.pack(pady=3, anchor='w')
        ttk.Button(bob_frame, text="Calculate Shared Secret", command=self.run_bob_secret).pack(pady=5, fill='x')
        self.bob_secret_label = ttk.Label(bob_frame, text="Shared Secret (s): ?")
        self.bob_secret_label.pack(pady=3, anchor='w')

        # 3. 암호화/복호화
        cipher_frame = ttk.LabelFrame(self.master, text="[Part 1] Step 3: Encrypt (Alice) and Decrypt (Bob)")
        cipher_frame.pack(padx=10, pady=10, fill="x")
        
        ttk.Label(cipher_frame, text="Alice's Plaintext:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.plaintext_entry = ttk.Entry(cipher_frame, width=60)
        self.plaintext_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(cipher_frame, text="Encrypt & Send to Bob", command=self.run_encrypt).grid(row=0, column=2, padx=5)

        ttk.Label(cipher_frame, text="Ciphertext (sent to Bob):").grid(row=1, column=0, sticky='w', padx=5)
        self.ciphertext_label = ttk.Label(cipher_frame, text="", wraplength=600)
        self.ciphertext_label.grid(row=1, column=1, sticky='w', padx=5)

        ttk.Button(cipher_frame, text="Bob Decrypts Message", command=self.run_decrypt).grid(row=2, column=2, padx=5)
        ttk.Label(cipher_frame, text="Bob's Decrypted Text:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.decrypted_label = ttk.Label(cipher_frame, text="", foreground="blue", font=("Helvetica", 10, "bold"))
        self.decrypted_label.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        # 4. 공격자 관점
        attacker_frame = ttk.LabelFrame(self.master, text="[Part 2] Attacker's View")
        attacker_frame.pack(padx=10, pady=10, fill="x")
        self.attacker_info_label = ttk.Label(attacker_frame, text="Attacker can only see public information.", justify=tk.LEFT)
        self.attacker_info_label.pack(pady=5, anchor='w')

        guess_frame = ttk.Frame(attacker_frame)
        guess_frame.pack(pady=5, fill='x')
        ttk.Label(guess_frame, text="Attacker's guess for Alice's private key (xa):").pack(side=tk.LEFT)
        self.attacker_guess_entry = ttk.Entry(guess_frame, width=20)
        self.attacker_guess_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(guess_frame, text="Try to Crack Secret & Decrypt", command=self.run_attacker_crack).pack(side=tk.LEFT)
        self.attacker_result_label = ttk.Label(guess_frame, text="", foreground="red")
        self.attacker_result_label.pack(side=tk.LEFT, padx=10)

    def run_generate_params(self):
        bits = int(self.key_size_var.get())
        self.p, self.g = generate_dh_params(bits)
        self.p_g_label.config(text=f"p and g generated ({bits}-bit).", foreground="green")
        self.update_attacker_view()

    def run_alice_keys(self):
        if not self.p: return messagebox.showerror("Error", "Generate p and g first.")
        self.xa, self.A = generate_person_keys(self.p, self.g)
        self.alice_priv_label.config(text=f"Private (xa): {self._short(self.xa)}")
        self.alice_pub_label.config(text=f"Public (A): {self._short(self.A)}")
        self.update_attacker_view()

    def run_bob_keys(self):
        if not self.p: return messagebox.showerror("Error", "Generate p and g first.")
        self.ya, self.B = generate_person_keys(self.p, self.g)
        self.bob_priv_label.config(text=f"Private (yb): {self._short(self.ya)}")
        self.bob_pub_label.config(text=f"Public (B): {self._short(self.B)}")
        self.update_attacker_view()

    def run_alice_secret(self):
        if not (self.xa and self.B): return messagebox.showerror("Error", "Generate Alice's keys and Bob's keys first.")
        self.s_alice = generate_shared_secret(self.B, self.xa, self.p)
        self.alice_secret_label.config(text=f"Shared Secret (s): {self._short(self.s_alice)}")

    def run_bob_secret(self):
        if not (self.ya and self.A): return messagebox.showerror("Error", "Generate Bob's keys and Alice's keys first.")
        self.s_bob = generate_shared_secret(self.A, self.ya, self.p)
        self.bob_secret_label.config(text=f"Shared Secret (s): {self._short(self.s_bob)}")
        if self.s_alice and self.s_alice == self.s_bob:
            messagebox.showinfo("Success", "Keys match! Alice and Bob have the same secret key.")

    def run_encrypt(self):
        if not self.s_alice: return messagebox.showerror("Error", "Alice must calculate the shared secret first.")
        plaintext = self.plaintext_entry.get()
        if not plaintext: return messagebox.showerror("Error", "Enter a message to encrypt.")
        shift_key = self.s_alice % 26
        self.ciphertext = shift_cipher(plaintext, shift_key)
        self.ciphertext_label.config(text=self.ciphertext)
        self.update_attacker_view()

    def run_decrypt(self):
        if not self.s_bob: return messagebox.showerror("Error", "Bob must calculate the shared secret first.")
        if not self.ciphertext: return messagebox.showerror("Error", "There is no ciphertext to decrypt.")
        shift_key = self.s_bob % 26
        decrypted_text = shift_cipher(self.ciphertext, shift_key, decrypt=True)
        self.decrypted_label.config(text=decrypted_text)
    
    def run_attacker_crack(self):
        if not (self.B and self.ciphertext): return messagebox.showerror("Error", "Not enough info. Generate keys and encrypt.")
        try:
            guess = int(self.attacker_guess_entry.get())
            cracked_s = generate_shared_secret(self.B, guess, self.p)
            cracked_shift = cracked_s % 26
            cracked_text = shift_cipher(self.ciphertext, cracked_shift, decrypt=True)
            self.attacker_result_label.config(text=f"Decryption with guessed key: '{cracked_text}'")
        except ValueError:
            messagebox.showerror("Error", "Guess must be an integer.")

    def update_attacker_view(self):
        p_val = self._short(self.p) if self.p else "?"
        g_val = self._short(self.g) if self.g else "?"
        A_val = self._short(self.A) if self.A else "?" # Alice's Public Value
        B_val = self._short(self.B) if self.B else "?" # Bob's Public Value
        C_val = self.ciphertext if self.ciphertext else "?" # Ciphertext
        
        info = (f"p: {p_val}\n"
                f"g: {g_val}\n"
                f"Alice's Public Value (A): {A_val}\n"
                f"Bob's Public Value (B): {B_val}\n"
                f"Ciphertext: {C_val}")
        self.attacker_info_label.config(text=info)

    def _short(self, val):
        s_val = str(val)
        return s_val if len(s_val) < 60 else f"{s_val[:30]}...{s_val[-30:]}"