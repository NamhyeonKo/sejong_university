# assignment5.py (Tkinter GUI - Uses AESCipher class from aes.py)

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import hashlib
import binascii
import traceback

# --- Import the AESCipher class from aes.py ---
try:
    # AESCipher class itself and global constants S_BOX, INV_S_BOX, RCON
    from aes import AESCipher, S_BOX, INV_S_BOX, RCON
except ImportError:
    messagebox.showerror("Import Error",
                         "Could not import AESCipher or constants from aes.py. "
                         "Make sure the file exists and is correctly structured.")
    exit()
except Exception as e:
    messagebox.showerror("Import Error", f"Error importing from aes.py: {e}")
    exit()


# --- Helper functions for UI: string <-> hex <-> bytes and padding ---
BLOCK_SIZE_BYTES = 16

def ui_text_to_bytes(text: str) -> bytes:
    return text.encode('utf-8')

def ui_bytes_to_text(byte_data: bytes) -> str:
    return byte_data.decode('utf-8', errors='replace')

def ui_bytes_to_hex(byte_data: bytes) -> str:
    return binascii.hexlify(byte_data).decode('ascii').upper()

def ui_hex_to_bytes(hex_str: str) -> bytes:
    try:
        return binascii.unhexlify(hex_str)
    except binascii.Error as e:
        raise ValueError(f"Invalid hexadecimal string provided: {e}")

def _pad_pkcs7_ui(data: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes: # Renamed for clarity
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len]) * padding_len
    return data + padding

def _unpad_pkcs7_ui(padded_data: bytes) -> bytes: # Renamed for clarity
    if not padded_data:
        raise ValueError("Padded data cannot be empty for unpadding.")
    padding_len = padded_data[-1]
    if padding_len == 0 or padding_len > len(padded_data) or padding_len > BLOCK_SIZE_BYTES:
        raise ValueError(f"Invalid PKCS#7 padding length: {padding_len}.")
    if not all(padded_data[i] == padding_len for i in range(len(padded_data) - padding_len, len(padded_data))):
        raise ValueError("Invalid PKCS#7 padding bytes.")
    return padded_data[:-padding_len]


class AESCryptoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES GUI (Uses AESCipher from aes.py)")
        self.geometry("950x750")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        self.aes_cipher_instance = None

        if not all(hasattr(AESCipher, m) for m in ['encrypt', 'decrypt', '_key_expansion', '_bytes_to_matrix', '_matrix_to_bytes']):
            messagebox.showerror("AESCipher Error", "AESCipher class from aes.py is missing expected methods. Please check aes.py.")
            self.destroy()
            return
        
        # Verify _matrix_to_bytes is callable (it's an instance method)
        # test_instance = AESCipher("0123456789abcdef") # Dummy key for test
        # if not callable(getattr(test_instance, "_matrix_to_bytes", None)):
        #     messagebox.showerror("AESCipher Error", "_matrix_to_bytes is not a callable method in AESCipher.")
        #     self.destroy()
        #     return
        # del test_instance

        self._build_ui()

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding="15 15 15 15")
        main_frame.grid(row=0, column=0, sticky="nsew")
        for i in range(2): main_frame.columnconfigure(i, weight=1)
        main_frame.rowconfigure(11, weight=1)

        ttk.Label(main_frame, text="1. Input Plaintext/Ciphertext (English Text for Encrypt, Hex for Decrypt):").grid(row=0, column=0, sticky="w", pady=(0,5))
        self.input_text_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.input_text_var, width=35).grid(row=1, column=0, sticky="ew", padx=(0,10))

        ttk.Label(main_frame, text="2. Input Key (16-char ASCII for AES-128):").grid(row=0, column=1, sticky="w", pady=(0,5))
        self.input_key_var = tk.StringVar()
        self.key_length_var = tk.StringVar(value="128")
        key_entry_frame = ttk.Frame(main_frame)
        key_entry_frame.grid(row=1, column=1, sticky="ew")
        key_entry_frame.columnconfigure(0, weight=1)
        ttk.Entry(key_entry_frame, textvariable=self.input_key_var, width=28).grid(row=0, column=0, sticky="ew")
        ttk.Label(key_entry_frame, text="Key Bits:").grid(row=0, column=1, sticky="w", padx=(10,2))
        cb = ttk.Combobox(key_entry_frame, textvariable=self.key_length_var, values=["128"], width=5, state="readonly")
        cb.set("128")
        cb.grid(row=0, column=2, sticky="w")

        ttk.Button(main_frame, text="3. Initialize AESCipher & Show Round Keys", command=self._on_generate_keys).grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Label(main_frame, text="AESCipher Round Keys (AES-128, Hex Matrices):").grid(row=3, column=0, sticky="w", columnspan=2, pady=(10,0))
        self.round_key_output = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=70, height=10, state='disabled', font=('Courier New', 9))
        self.round_key_output.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=(0,10))

        ttk.Label(main_frame, text="Intermediate Process Log (First Block - Simulating with AESCipher methods):").grid(row=5, column=0, sticky="w", columnspan=2, pady=(10,0))
        self.intermediate_log_output = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=70, height=5, state='disabled', font=('Courier New', 9))
        self.intermediate_log_output.grid(row=6, column=0, columnspan=2, sticky="nsew", pady=(0,10))

        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=10)
        ttk.Button(button_frame, text="Encrypt", command=lambda: self._run_aes("encrypt")).pack(side="left", padx=20, ipadx=10, ipady=5)
        ttk.Button(button_frame, text="Decrypt", command=lambda: self._run_aes("decrypt")).pack(side="left", padx=20, ipadx=10, ipady=5)

        ttk.Label(main_frame, text="Final Result (Hex for Encryption, English Text for Decryption):").grid(row=8, column=0, sticky="w", columnspan=2, pady=(10,0))
        self.final_result_var = tk.StringVar(value="Result will appear here")
        ttk.Label(main_frame, textvariable=self.final_result_var, font=('Arial', 12, 'bold'), wraplength=800, justify='left').grid(row=9, column=0, columnspan=2, sticky="w")

        ttk.Label(main_frame, text="Full Process Log:").grid(row=10, column=0, sticky="w", columnspan=2, pady=(10,0))
        self.log_output = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=80, height=15, state='disabled', font=('Courier New', 9))
        self.log_output.grid(row=11, column=0, columnspan=2, sticky="nsew", pady=(0,10))

    def _update_output_widget(self, widget, text):
        widget.config(state='normal')
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)
        widget.config(state='disabled')

    def _log_message(self, message, target_widget=None):
        if target_widget is None: target_widget = self.log_output
        current_content = target_widget.get(1.0, tk.END).strip()
        message_to_insert = ("\n" if current_content else "") + message
        target_widget.config(state='normal')
        target_widget.insert(tk.END, message_to_insert)
        target_widget.config(state='disabled')
        target_widget.see(tk.END)

    def _clear_logs_and_results(self, clear_round_keys_display=True):
        self.final_result_var.set("Result will appear here")
        if clear_round_keys_display: self._update_output_widget(self.round_key_output, "")
        self._update_output_widget(self.intermediate_log_output, "")
        if self.log_output.get(1.0, tk.END).strip():
             self._log_message("\n--- Log Cleared for New Operation ---")

    def _on_generate_keys(self):
        input_key_text = self.input_key_var.get().strip()
        self.aes_cipher_instance = None
        self._clear_logs_and_results(clear_round_keys_display=True)
        self._log_message("--- Initializing AESCipher (AES-128 from aes.py) ---")

        if not input_key_text:
            messagebox.showerror("Input Error", "Please enter an English key (16 ASCII characters for AESCipher).")
            self._log_message("Key initialization failed: English key not provided.")
            return

        self._log_message(f"Input Key (English Text): '{input_key_text}'")
        
        key_for_class_str = input_key_text
        try:
            key_for_class_bytes_test = key_for_class_str.encode('ascii')
            if len(key_for_class_bytes_test) != 16:
                messagebox.showerror("Key Error", f"AESCipher class requires a 16-character ASCII key. Current key is {len(key_for_class_bytes_test)} ASCII bytes.")
                self._log_message(f"Key initialization failed: Key must be 16 ASCII characters. Provided: '{input_key_text}' (len {len(key_for_class_bytes_test)}).")
                return
        except UnicodeEncodeError:
            messagebox.showerror("Key Error", "Key contains non-ASCII characters. AESCipher class requires a 16-character ASCII key.")
            self._log_message(f"Key initialization failed: Key '{input_key_text}' contains non-ASCII characters.")
            return
        
        self._log_message(f"Key to be used for AESCipher (16-char ASCII): '{key_for_class_str}'")
        self._log_message(f"(Note: AESCipher class used is hardcoded for AES-128.)")

        try:
            self.aes_cipher_instance = AESCipher(key_for_class_str)
            round_keys_matrices = self.aes_cipher_instance.round_keys
            nr_rounds = self.aes_cipher_instance.Nr
            
            round_keys_display_str = f"AESCipher Round Keys (AES-128, {nr_rounds + 1} keys for {nr_rounds} rounds):\n"
            for i, rk_matrix in enumerate(round_keys_matrices): # rk_matrix is [row][col]
                round_keys_display_str += f"Round Key {i}:\n"
                for r_idx, row_data in enumerate(rk_matrix):
                    hex_row = [ui_bytes_to_hex(bytes([b])) for b in row_data]
                    round_keys_display_str += f"  Row {r_idx}: {hex_row}\n"
            
            self._update_output_widget(self.round_key_output, round_keys_display_str.strip())
            self._log_message(f"AESCipher instance created. {len(round_keys_matrices)} round keys displayed.")
            messagebox.showinfo("Success", "AESCipher initialized (AES-128). Round keys displayed.")

        except ValueError as ve: 
             messagebox.showerror("AESCipher Init Error", f"Error initializing AESCipher: {ve}")
             self._log_message(f"Error initializing AESCipher: {ve}")
        except Exception as e:
            tb_str = traceback.format_exc()
            messagebox.showerror("Key Setup Error", f"Error during AES key setup: {e}")
            self._log_message(f"Error during AES key setup: {e}\n{tb_str}")

    def _generate_intermediate_log_for_block(self, first_block_initial_bytes: bytes, mode:str) -> str:
        if not self.aes_cipher_instance:
            return "AESCipher instance not available for intermediate log."

        instance = self.aes_cipher_instance
        log_lines = []
        
        # IMPORTANT: The AESCipher's _bytes_to_matrix as provided is state[col][row].
        # However, its _shift_rows, _mix_columns, _add_round_key, _sub_bytes expect state[row][col]
        # for standard AES behavior. If _bytes_to_matrix in aes.py is not corrected
        # to output state[row][col], the class's main encrypt/decrypt will be non-standard.
        # For this logging function, we will proceed ASSUMING that for these _internal_ calls,
        # we should prepare the state in [row][col] format.

        def _local_bytes_to_matrix_row_major(data: bytes) -> list[list[int]]:
            # This is the CORRECTED version for state[row][col]
            s = [[0]*4 for _ in range(4)]
            for r_idx in range(4):
                for c_idx in range(4):
                    s[r_idx][c_idx] = data[r_idx + 4*c_idx]
            return s

        # Use the class's _matrix_to_bytes which is correct for state[row][col] display.
        # It's the second definition in your class: def _matrix_to_bytes(self, state):
        
        state_rc_for_log = _local_bytes_to_matrix_row_major(first_block_initial_bytes)
        
        log_lines.append(f"--- {mode.capitalize()} First Block Details (Simulating with AESCipher methods) ---")
        log_lines.append(f"Initial State (Hex, Row-Major): {ui_bytes_to_hex(instance._matrix_to_bytes(state_rc_for_log))}")

        round_keys = instance.round_keys # These are rk[row][col] from AESCipher
        Nr = instance.Nr                 # This is 10 for AES-128

        current_state_for_steps = [row[:] for row in state_rc_for_log] # Deep copy

        try:
            if mode == "encrypt":
                log_lines.append(f"\nRound 0 (AddRoundKey with K0):")
                instance._add_round_key(current_state_for_steps, round_keys[0])
                log_lines.append(f"  State after AddRoundKey(K0): {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")

                if Nr >= 1:
                    log_lines.append(f"\nRound 1:")
                    instance._sub_bytes(current_state_for_steps)
                    log_lines.append(f"  After SubBytes: {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")
                    instance._shift_rows(current_state_for_steps)
                    log_lines.append(f"  After ShiftRows: {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")
                    if Nr > 1:
                         instance._mix_columns(current_state_for_steps)
                         log_lines.append(f"  After MixColumns: {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")
                    instance._add_round_key(current_state_for_steps, round_keys[1])
                    log_lines.append(f"  After AddRoundKey(K1): {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")
            
            elif mode == "decrypt":
                log_lines.append(f"\nInitial AddRoundKey (with K{Nr}):")
                instance._add_round_key(current_state_for_steps, round_keys[Nr])
                log_lines.append(f"  State after AddRoundKey(K{Nr}): {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")
                
                if Nr >=1:
                    log_lines.append(f"\nEffective Inverse Round (using K{Nr-1}):")
                    instance._inv_shift_rows(current_state_for_steps)
                    log_lines.append(f"  After InvShiftRows: {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")
                    instance._inv_sub_bytes(current_state_for_steps)
                    log_lines.append(f"  After InvSubBytes: {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")
                    instance._add_round_key(current_state_for_steps, round_keys[Nr-1])
                    log_lines.append(f"  After AddRoundKey(K{Nr-1}): {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")
                    if Nr-1 > 0:
                        instance._inv_mix_columns(current_state_for_steps)
                        log_lines.append(f"  After InvMixColumns: {ui_bytes_to_hex(instance._matrix_to_bytes(current_state_for_steps))}")
        except Exception as log_ex:
            log_lines.append(f"Error during intermediate log generation: {log_ex}")
            self._log_message(f"TRACEBACK for intermediate log error: {traceback.format_exc()}")


        return "\n".join(log_lines)


    def _run_aes(self, mode: str):
        input_raw = self.input_text_var.get().strip()
        self._update_output_widget(self.intermediate_log_output, "") # Clear specific logs
        self.final_result_var.set("Processing...")

        if not self.aes_cipher_instance:
            messagebox.showerror("Error", "Please initialize AESCipher by generating/setting keys first.")
            self._log_message("AES operation failed: AESCipher not initialized.")
            self.final_result_var.set("Result will appear here")
            return

        if not input_raw:
            messagebox.showerror("Input Error", f"Please enter {'plaintext (English)' if mode == 'encrypt' else 'ciphertext (Hex)'}.")
            self._log_message(f"AES operation failed: No input provided.")
            self.final_result_var.set("Result will appear here")
            return
        
        self._log_message(f"\n--- AES {mode.upper()}ION STARTED (Using AESCipher Class - AES-128) ---")
        self._log_message(f"Input ({'English Text' if mode == 'encrypt' else 'Hex Ciphertext'}): {input_raw}")

        first_block_intermediate_log_str = "Intermediate log for the first block will be generated."

        try:
            if mode == "encrypt":
                # AESCipher.encrypt expects a string and handles padding using its own _pad and _str_to_bytes (ASCII).
                # It returns a hex string.
                self._log_message(f"Plaintext for AESCipher.encrypt: '{input_raw}'")
                final_output_hex = self.aes_cipher_instance.encrypt(input_raw) # This uses class's ASCII and padding
                
                # For intermediate log, use UI's UTF-8 handling for plaintext then class's padding
                temp_plaintext_bytes_for_log = self.aes_cipher_instance._str_to_bytes(input_raw) # Use class's str_to_bytes
                temp_padded_bytes_for_log = self.aes_cipher_instance._pad(temp_plaintext_bytes_for_log) # Use class's padding
                
                if temp_padded_bytes_for_log:
                     first_block_bytes_for_log = temp_padded_bytes_for_log[:BLOCK_SIZE_BYTES]
                     first_block_intermediate_log_str = self._generate_intermediate_log_for_block(first_block_bytes_for_log, "encrypt")
                
                self.final_result_var.set(f"{final_output_hex}")
                self._log_message(f"\n--- AES ENCRYPTION COMPLETE (via AESCipher.encrypt) ---")
                self._log_message(f"Final Full Ciphertext (Hex): {final_output_hex}")

            elif mode == "decrypt":
                ciphertext_hex_input = input_raw.replace(" ", "").upper()
                # Basic validation for hex string
                if not ciphertext_hex_input or len(ciphertext_hex_input) % 2 != 0 :
                    msg = f"Ciphertext hex length ({len(ciphertext_hex_input)}) must be a non-zero even number."
                    messagebox.showerror("Input Error", msg)
                    self._log_message(f"AES decryption failed: {msg}")
                    self.final_result_var.set("Result will appear here")
                    return
                try:
                    # Test if it's valid hex before passing to class, to give clearer UI error
                    ui_hex_to_bytes(ciphertext_hex_input) 
                except ValueError:
                    messagebox.showerror("Input Error", "Ciphertext must be a valid hexadecimal string.")
                    self._log_message("AES decryption failed: Invalid characters in ciphertext hex.")
                    self.final_result_var.set("Result will appear here")
                    return
                
                self._log_message(f"Ciphertext for AESCipher.decrypt (Hex): {ciphertext_hex_input}")
                decrypted_text = self.aes_cipher_instance.decrypt(ciphertext_hex_input)

                # For intermediate log:
                try:
                    ciphertext_bytes_for_log = ui_hex_to_bytes(ciphertext_hex_input) # Use UI helper for conversion
                    if ciphertext_bytes_for_log:
                        first_block_bytes_for_log = ciphertext_bytes_for_log[:BLOCK_SIZE_BYTES]
                        first_block_intermediate_log_str = self._generate_intermediate_log_for_block(first_block_bytes_for_log, "decrypt")
                except ValueError as e_hex: # Should have been caught above
                    self._log_message(f"Could not generate intermediate log: Invalid hex for first block - {e_hex}")

                self.final_result_var.set(f"{decrypted_text}")
                self._log_message(f"\n--- AES DECRYPTION COMPLETE (via AESCipher.decrypt) ---")
                self._log_message(f"Final Decrypted Plaintext (ASCII from class): {decrypted_text}")

            self._update_output_widget(self.intermediate_log_output, first_block_intermediate_log_str.strip())
            self._log_message(f"\nAES {mode.upper()}ION FINISHED SUCCESSFULLY.")
            messagebox.showinfo("Success", f"AES {mode.upper()}ion complete!")

        except ValueError as ve:
            tb_str = traceback.format_exc()
            messagebox.showerror("Operation Error", f"AESCipher Error: {ve}")
            self._log_message(f"Error during AES {mode}ion: {ve}\n{tb_str}")
            self.final_result_var.set("Error occurred")
        except Exception as e:
            tb_str = traceback.format_exc()
            messagebox.showerror("Unexpected Error", f"An unexpected error occurred: {e}")
            self._log_message(f"Unexpected error during AES {mode}ion: {e}\n{tb_str}")
            self.final_result_var.set("Error occurred")
