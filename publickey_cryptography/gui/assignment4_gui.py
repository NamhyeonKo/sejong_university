import tkinter as tk
from tkinter import ttk, scrolledtext
from tkinter import messagebox

# Import DES functions from your 'des_algorithm.py' library file
from crypto_pkg.des_gemini import (
    hex_to_bin, bin_to_hex, permute,
    generate_subkeys,
    des_operation
)

class DESCryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Assignment 4: Historical Encryption (DES)")
        self.geometry("900x750") # Increased size for more outputs
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.encryption_keys = [] # To store the generated K1 to K16

        self._build_ui()

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding="15 15 15 15")
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(7, weight=1) # Make the output area expandable

        # --- Input Section ---
        ttk.Label(main_frame, text="1. Input Plaintext/Ciphertext (16 Hex characters):").grid(row=0, column=0, sticky="w", pady=(0,5))
        self.input_text_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.input_text_var, width=30).grid(row=1, column=0, sticky="ew", padx=(0,10))

        ttk.Label(main_frame, text="2. Input Key (16 Hex characters):").grid(row=0, column=1, sticky="w", pady=(0,5))
        self.input_key_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.input_key_var, width=30).grid(row=1, column=1, sticky="ew")

        # --- Key Generation Button ---
        ttk.Button(main_frame, text="3. Generate 16 Subkeys", command=self._on_generate_keys).grid(row=2, column=0, columnspan=2, pady=10)

        # --- Key Generation Output ---
        ttk.Label(main_frame, text="Generated Subkeys (K1-K16):").grid(row=3, column=0, sticky="w", columnspan=2, pady=(10,0))
        self.subkey_output = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=60, height=8, state='disabled', font=('Courier New', 10))
        self.subkey_output.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=(0,10))

        # --- L1 and R1 Display ---
        ttk.Label(main_frame, text="L1 and R1 (Binary) after 1st Round:").grid(row=5, column=0, sticky="w", columnspan=2, pady=(10,0))
        self.l1_r1_output = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=60, height=3, state='disabled', font=('Courier New', 10))
        self.l1_r1_output.grid(row=6, column=0, columnspan=2, sticky="nsew", pady=(0,10))

        # --- S-box values ---
        ttk.Label(main_frame, text="S-box outputs (Binary) and P-box output (Binary) of 1st Round:").grid(row=7, column=0, sticky="w", columnspan=2, pady=(10,0))
        self.sbox_pbox_output = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=60, height=4, state='disabled', font=('Courier New', 10))
        self.sbox_pbox_output.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=(0,10))

        # --- Execution Buttons ---
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=9, column=0, columnspan=2, pady=10)
        ttk.Button(button_frame, text="Encrypt", command=lambda: self._run_des("encrypt")).pack(side="left", padx=20, ipadx=10, ipady=5)
        ttk.Button(button_frame, text="Decrypt", command=lambda: self._run_des("decrypt")).pack(side="left", padx=20, ipadx=10, ipady=5)

        # --- Final Result Output ---
        ttk.Label(main_frame, text="Final Result (Hex):").grid(row=10, column=0, sticky="w", columnspan=2, pady=(10,0))
        self.final_result_var = tk.StringVar(value="Result will appear here")
        ttk.Label(main_frame, textvariable=self.final_result_var, font=('Arial', 12, 'bold')).grid(row=11, column=0, sticky="w", columnspan=2)

        # --- Detailed Log Output ---
        ttk.Label(main_frame, text="Detailed Process Log:").grid(row=12, column=0, sticky="w", columnspan=2, pady=(10,0))
        self.log_output = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=80, height=15, state='disabled', font=('Courier New', 9))
        self.log_output.grid(row=13, column=0, columnspan=2, sticky="nsew", pady=(0,10))
        main_frame.rowconfigure(13, weight=1) # Allow log to expand

    def _update_output_widget(self, widget, text):
        widget.config(state='normal')
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)
        widget.config(state='disabled')

    def _log_message(self, message):
        self.log_output.config(state='normal')
        self.log_output.insert(tk.END, message + "\n")
        self.log_output.config(state='disabled')
        self.log_output.see(tk.END) # Scroll to the end

    def _on_generate_keys(self):
        key_hex = self.input_key_var.get().strip().upper()
        self.encryption_keys = [] # Clear previous keys
        self._update_output_widget(self.subkey_output, "")
        self._update_output_widget(self.l1_r1_output, "")
        self._update_output_widget(self.sbox_pbox_output, "")
        self.final_result_var.set("Result will appear here")
        self._update_output_widget(self.log_output, "")

        if not key_hex:
            messagebox.showerror("Input Error", "Please enter a hexadecimal key.")
            return
        if len(key_hex) != 16 or not all(c in '0123456789ABCDEF' for c in key_hex):
            messagebox.showerror("Input Error", "Key must be 16 hexadecimal characters (64 bits).")
            return

        try:
            self._log_message("--- Generating Subkeys ---")
            # Call generate_subkeys from the imported des_algorithm module
            keys, c_hist, d_hist, initial_k_bin = generate_subkeys(key_hex)
            self.encryption_keys = keys # Store for encryption/decryption

            # Display initial K, C0, D0
            log_str = f"K (hex) = {key_hex}\n"
            log_str += f"K (binary) = {initial_k_bin}\n"
            log_str += f"K+ (PC-1 output) = {permute(initial_k_bin, [
                57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
                63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4
            ])}\n" # Using hardcoded pc1_table as it's not imported.
            log_str += f"C0 = {c_hist[0]}\n"
            log_str += f"D0 = {d_hist[0]}\n"

            # Display all C and D values and K_i
            subkeys_display = "Subkeys (K1-K16):\n"
            for i in range(1, 17):
                log_str += f"C{i} = {c_hist[i]}\n"
                log_str += f"D{i} = {d_hist[i]}\n"
                log_str += f"K{i} = {keys[i-1]}\n\n"
                subkeys_display += f"K{i}: {keys[i-1]}\n"

            self._update_output_widget(self.subkey_output, subkeys_display)
            self._log_message(log_str) # Log C and D histories and K_i

            messagebox.showinfo("Success", "16 subkeys generated successfully!")

        except Exception as e:
            messagebox.showerror("Error", f"Error during key generation: {e}")
            self._log_message(f"Error during key generation: {e}")

    def _run_des(self, mode: str):
        input_hex = self.input_text_var.get().strip().upper()
        self.final_result_var.set("Result will appear here")
        self._update_output_widget(self.l1_r1_output, "")
        self._update_output_widget(self.sbox_pbox_output, "")
        self._update_output_widget(self.log_output, "") # Clear previous log

        if not self.encryption_keys:
            messagebox.showerror("Error", "Please generate subkeys first.")
            return

        if not input_hex:
            messagebox.showerror("Input Error", f"Please enter the {mode}text.")
            return
        if len(input_hex) != 16 or not all(c in '0123456789ABCDEF' for c in input_hex):
            messagebox.showerror("Input Error", f"{'Plaintext' if mode == 'encrypt' else 'Ciphertext'} must be 16 hexadecimal characters (64 bits).")
            return

        try:
            # Call des_operation from the imported des_algorithm module
            results = des_operation(input_hex, self.encryption_keys, mode, self._log_message)
            output_bin = results['final_output_bin']
            l1_val = results['l1_val']
            r1_val = results['r1_val']
            s_box_out_r1 = results['s_box_out_r1']
            p_box_out_r1 = results['p_box_out_r1']

            output_hex = bin_to_hex(output_bin)
            self.final_result_var.set(f"{output_hex}")

            # Display L1 and R1 and S-box values from the first round
            l1_r1_str = f"L1: {l1_val}\nR1: {r1_val}"
            self._update_output_widget(self.l1_r1_output, l1_r1_str)

            sbox_pbox_str = f"S-box output (binary): {s_box_out_r1}\nP-box output (binary): {p_box_out_r1}"
            self._update_output_widget(self.sbox_pbox_output, sbox_pbox_str)

            messagebox.showinfo("Success", f"DES {mode}ion complete!")

        except Exception as e:
            messagebox.showerror("Error", f"Error during DES {mode}ion: {e}")
            self._log_message(f"Error during DES {mode}ion: {e}")
