import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from elgamal import generate_keys, encrypt, decrypt

class ElGamalGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("ElGamal Cryptosystem Simulator (Scrollable)")
        # 창 크기를 조절해도 내용이 잘리지 않도록 초기 크기를 적절히 설정
        self.master.geometry("750x600") 

        # 앨리스의 키와 암호문을 저장할 변수
        self.alice_public_key = None
        self.alice_private_key = None
        self.ciphertext = None

        # 스타일 설정
        style = ttk.Style()
        style.configure("TButton", padding=5, font=('Helvetica', 10))
        style.configure("TLabel", padding=5, font=('Helvetica', 10))
        style.configure("TEntry", padding=5, font=('Helvetica', 10))
        style.configure("Header.TLabel", font=('Helvetica', 12, 'bold'))

        # --- 스크롤 기능 설정 ---
        # 1. 모든 위젯을 담을 컨테이너 프레임 생성
        container = ttk.Frame(self.master)
        container.pack(fill=tk.BOTH, expand=True)

        # 2. 캔버스 위젯과 스크롤바 위젯 생성
        self.canvas = tk.Canvas(container)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        
        # 3. 스크롤 가능한 프레임 생성 (모든 내용은 이 프레임 안에 들어감)
        self.scrollable_frame = ttk.Frame(self.canvas)

        # 4. 스크롤 가능한 프레임의 크기가 변경될 때, 캔버스의 스크롤 영역을 업데이트하도록 바인딩
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )
        
        # 5. 캔버스에 스크롤 가능한 프레임을 창으로 추가
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        # 6. 캔버스와 스크롤바를 화면에 배치
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # --- 위젯 생성 호출 ---
        # 이제 위젯들은 self.scrollable_frame 안에 생성됨
        self._create_widgets()

    def _create_widgets(self):
        # 변경: 모든 LabelFrame의 부모를 self.master가 아닌 self.scrollable_frame으로 지정
        
        # 1. 키 생성 파트
        setup_frame = ttk.LabelFrame(self.scrollable_frame, text="1. Setup & Key Generation (Alice)", padding="10")
        setup_frame.pack(fill=tk.X, expand=True, pady=10, padx=10)
        # ... (이하 위젯 배치 코드는 이전과 동일) ...
        ttk.Label(setup_frame, text="소수 (P):").grid(row=0, column=0, sticky=tk.W)
        self.p_var = tk.StringVar(value="1019")
        ttk.Entry(setup_frame, textvariable=self.p_var, width=30).grid(row=0, column=1, sticky=tk.EW)
        ttk.Label(setup_frame, text="생성원 (g):").grid(row=1, column=0, sticky=tk.W)
        self.g_var = tk.StringVar(value="23")
        ttk.Entry(setup_frame, textvariable=self.g_var, width=30).grid(row=1, column=1, sticky=tk.EW)
        ttk.Button(setup_frame, text="Generate Alice's Keys", command=self.generate_alice_keys).grid(row=2, column=0, columnspan=2, pady=5)
        ttk.Label(setup_frame, text="Alice Public Key (p, g, e):").grid(row=3, column=0, sticky=tk.W)
        self.alice_pk_var = tk.StringVar(value="Not generated yet")
        ttk.Label(setup_frame, textvariable=self.alice_pk_var, foreground="blue", wraplength=450).grid(row=3, column=1, sticky=tk.W)
        ttk.Label(setup_frame, text="Alice Private Key (d):").grid(row=4, column=0, sticky=tk.W)
        self.alice_sk_var = tk.StringVar(value="Not generated yet")
        ttk.Label(setup_frame, textvariable=self.alice_sk_var, foreground="red").grid(row=4, column=1, sticky=tk.W)
        setup_frame.columnconfigure(1, weight=1)

        # 2. 암호화 파트
        encrypt_frame = ttk.LabelFrame(self.scrollable_frame, text="2. Encryption (Bob)", padding="10")
        encrypt_frame.pack(fill=tk.X, expand=True, pady=10, padx=10)
        ttk.Label(encrypt_frame, text="Plaintext Message:").grid(row=0, column=0, sticky=tk.W)
        self.msg_var = tk.StringVar(value="Hello Sejong University! This is a test message for ElGamal protocol.")
        ttk.Entry(encrypt_frame, textvariable=self.msg_var).grid(row=0, column=1, sticky=tk.EW)
        ttk.Button(encrypt_frame, text="Encrypt Message (by Bob)", command=self.bob_encrypt_message).grid(row=1, column=0, columnspan=2, pady=5)
        ttk.Label(encrypt_frame, text="Ciphertext (Y1, Y2):").grid(row=2, column=0, sticky=tk.W)
        self.cipher_var = tk.StringVar(value="Not encrypted yet")
        ttk.Label(encrypt_frame, textvariable=self.cipher_var, foreground="green", wraplength=450).grid(row=2, column=1, sticky=tk.W)
        encrypt_frame.columnconfigure(1, weight=1)

        # 3. 공격자 파트
        attacker_frame = ttk.LabelFrame(self.scrollable_frame, text="3. Attacker's View & Attempt", padding="10")
        attacker_frame.pack(fill=tk.X, expand=True, pady=10, padx=10)
        ttk.Label(attacker_frame, text="Visible to Attacker:", font=('Helvetica', 10, 'italic')).grid(row=0, column=0, columnspan=2, sticky=tk.W)
        ttk.Label(attacker_frame, text="  - Public Key (p,g,e):", foreground="blue").grid(row=1, column=0, sticky=tk.W)
        ttk.Label(attacker_frame, textvariable=self.alice_pk_var, wraplength=450).grid(row=1, column=1, sticky=tk.W)
        ttk.Label(attacker_frame, text="  - Ciphertext (Y1,Y2):", foreground="green").grid(row=2, column=0, sticky=tk.W)
        ttk.Label(attacker_frame, textvariable=self.cipher_var, wraplength=450).grid(row=2, column=1, sticky=tk.W)
        ttk.Label(attacker_frame, text="Attacker's Guess for 'd':").grid(row=3, column=0, pady=(10,0), sticky=tk.W)
        self.guess_var = tk.StringVar()
        ttk.Entry(attacker_frame, textvariable=self.guess_var, width=20).grid(row=3, column=1, pady=(10,0), sticky=tk.W)
        ttk.Button(attacker_frame, text="Try to Decrypt with Guess", command=self.attacker_try_decrypt).grid(row=4, column=0, columnspan=2, pady=5)
        ttk.Label(attacker_frame, text="Attack Result:").grid(row=5, column=0, sticky=tk.W)
        self.attack_res_var = tk.StringVar(value="...")
        ttk.Label(attacker_frame, textvariable=self.attack_res_var, foreground="magenta", wraplength=450).grid(row=5, column=1, sticky=tk.W)
        attacker_frame.columnconfigure(1, weight=1)
        
        # 4. 복호화 파트
        decrypt_frame = ttk.LabelFrame(self.scrollable_frame, text="4. Decryption (Alice)", padding="10")
        decrypt_frame.pack(fill=tk.X, expand=True, pady=10, padx=10)
        ttk.Button(decrypt_frame, text="Decrypt with Alice's REAL Key", command=self.alice_decrypt_message).pack(pady=5)
        ttk.Label(decrypt_frame, text="Decrypted Message:").pack()
        self.decrypted_msg_var = tk.StringVar(value="...")
        ttk.Label(decrypt_frame, textvariable=self.decrypted_msg_var, foreground="blue", font=('Helvetica', 11, 'bold')).pack()

        # 5. 로그
        log_frame = ttk.LabelFrame(self.scrollable_frame, text="Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10, padx=10)
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
    
    # --- 나머지 이벤트 핸들러 함수들은 이전과 동일 ---
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def generate_alice_keys(self):
        try:
            p = int(self.p_var.get())
            g = int(self.g_var.get())
        except ValueError:
            messagebox.showerror("Input Error", "P and G must be integers.")
            return
        
        success, result = generate_keys(p, g)
        
        if success:
            self.alice_public_key = result['public_key']
            self.alice_private_key = result['private_key']
            
            pk = self.alice_public_key
            sk = self.alice_private_key
            
            self.alice_pk_var.set(f"p={pk[0]}, g={pk[1]}, e={pk[2]}")
            self.alice_sk_var.set(f"{sk} (This is secret!)")
            self.log(f"✅ Alice's keys generated. Public Key: {pk}")
        else:
            messagebox.showerror("Key Generation Error", result)
            self.log(f"❌ Key Generation Error: {result}")

    def bob_encrypt_message(self):
        if not self.alice_public_key:
            messagebox.showwarning("Warning", "Generate Alice's keys first.")
            return
        
        message_str = self.msg_var.get()
        if not message_str:
            messagebox.showwarning("Warning", "Message cannot be empty.")
            return
            
        try:
            message_int = int.from_bytes(message_str.encode('utf-8'), 'big')
            self.ciphertext = encrypt(message_int, self.alice_public_key)
            self.cipher_var.set(f"Y1={self.ciphertext[0]}, \nY2={self.ciphertext[1]}")
            self.log(f"📨 Message '{message_str}' encrypted by Bob.")
            self.log(f"   Ciphertext: {self.ciphertext}")
        except ValueError as e:
            messagebox.showerror("Encryption Error", str(e))
            self.log(f"❌ Encryption Error: {e}")

    def alice_decrypt_message(self):
        if not self.ciphertext:
            messagebox.showwarning("Warning", "Encrypt a message first.")
            return

        p = self.alice_public_key[0]
        decrypted_int = decrypt(self.ciphertext, p, self.alice_private_key)
        
        try:
            byte_len = (decrypted_int.bit_length() + 7) // 8 or 1
            decrypted_str = decrypted_int.to_bytes(byte_len, 'big').decode('utf-8')
            self.decrypted_msg_var.set(decrypted_str)
            self.log(f"🔑 Alice decrypted the message: '{decrypted_str}'")
        except Exception as e:
            self.decrypted_msg_var.set("Decryption failed (Decoding Error)")
            self.log(f"❌ Decryption Error: {e}")

    def attacker_try_decrypt(self):
        if not self.ciphertext:
            messagebox.showwarning("Warning", "No ciphertext to attack.")
            return
        
        try:
            guess_d = int(self.guess_var.get())
        except ValueError:
            messagebox.showerror("Input Error", "Guessed key 'd' must be an integer.")
            return

        p = self.alice_public_key[0]
        
        m_int = decrypt(self.ciphertext, p, guess_d)

        try:
            byte_len = (m_int.bit_length() + 7) // 8 if m_int > 0 else 1
            attack_result_str = m_int.to_bytes(byte_len, 'big').decode('utf-8', errors='replace')
            self.attack_res_var.set(f"'{attack_result_str}'")
            self.log(f"⚔️ Attacker tried key {guess_d}, got result: '{attack_result_str}'")
        except Exception:
            self.attack_res_var.set("Failed to decode result.")
            self.log(f"⚔️ Attacker tried key {guess_d}, but failed to decode.")
