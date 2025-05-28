# AES S-Box (Substitution Box)
# Based on [cite: 108, 127, 128]
S_BOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

# Inverse S-Box
INV_S_BOX = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
)

# Round Constant (RCON)
# Based on [cite: 112, 114] - RCON[j] for round j. Using 1-based indexing for RCON values.
RCON = [
    None,  # RCON[0] is not used
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],  # For x^8 mod m(x) where m(x) = x^8+x^4+x^3+x+1
    [0x36, 0x00, 0x00, 0x00],
]

class AESCipher:
    def __init__(self, key_str):
        self.Nk = 4  # Number of 32-bit words in the key (AES-128)
        self.Nb = 4  # Number of 32-bit words in a block (AES-128)
        self.Nr = 10 # Number of rounds for AES-128 [cite: 91]
        
        key_bytes = self._str_to_bytes(key_str)
        if len(key_bytes) != 16: # AES-128 key is 16 bytes
            raise ValueError("Key must be 16 bytes long for AES-128.")
            
        self.round_keys = self._key_expansion(key_bytes)

    def _str_to_bytes(self, s):
        return s.encode('ascii') # As per assignment [cite: 173] and examples [cite: 95]

    def _bytes_to_str(self, b):
        return b.decode('ascii')

    def _pad(self, data):
        # PKCS#7 padding
        padding_len = 16 - (len(data) % 16)
        padding = bytes([padding_len] * padding_len)
        return data + padding

    def _unpad(self, data):
        padding_len = data[-1]
        if not (1 <= padding_len <= 16):
             raise ValueError("Invalid padding value")
        for i in range(1, padding_len + 1):
            if data[-i] != padding_len:
                raise ValueError("Invalid padding bytes")
        return data[:-padding_len]

    def _bytes_to_matrix(self, data):
        # Converts 16-byte data to a 4x4 state matrix (column major)
        return [list(data[i::4]) for i in range(4)]

    def _matrix_to_bytes(self, matrix):
        # Converts a 4x4 state matrix back to 16-byte data (column major)
        return bytes(matrix[0][j] ^ matrix[1][j] ^ matrix[2][j] ^ matrix[3][j] for j in range(4) for i in range(4)) # Incorrect logic
    
    def _matrix_to_bytes(self, state):
        data = bytearray(16)
        for r in range(4):
            for c in range(4):
                data[r + 4*c] = state[r][c]
        return bytes(data)

    ## AES Key Expansion ##
    # Based on [cite: 93, 97, 100, 104, 105, 112, 118]
    def _key_expansion(self, key_bytes):
        w = [([0] * 4) for _ in range(self.Nb * (self.Nr + 1))] # Array of 4-byte words

        # Fill first Nk words from the key
        for i in range(self.Nk):
            w[i] = [key_bytes[4*i], key_bytes[4*i+1], key_bytes[4*i+2], key_bytes[4*i+3]]

        for i in range(self.Nk, self.Nb * (self.Nr + 1)):
            temp = list(w[i-1]) # Make a copy

            if i % self.Nk == 0:
                # RotWord: Rotate left [a0,a1,a2,a3] -> [a1,a2,a3,a0] [cite: 105]
                temp = temp[1:] + temp[:1]
                
                # SubWord: Apply S-Box to each byte [cite: 105, 107]
                temp = [S_BOX[b] for b in temp]
                
                # XOR with Rcon [cite: 105, 112]
                rcon_val = RCON[i // self.Nk]
                for j in range(4):
                    temp[j] ^= rcon_val[j]
            
            # For AES-256 (Nk=8), if i % Nk == 4, an extra SubWord is applied to temp
            # Not needed for AES-128 (Nk=4)

            # XOR with w[i-Nk]
            for j in range(4):
                w[i][j] = w[i-self.Nk][j] ^ temp[j]
        
        # Group words into round key matrices (4x4)
        # Each round key is 4 words. Word k becomes column k of the key matrix.
        expanded_keys = []
        for i in range(self.Nr + 1):
            round_key_matrix = [[0]*4 for _ in range(4)]
            base = i * self.Nb
            for r in range(4): # row
                for c in range(4): # col
                    round_key_matrix[r][c] = w[base + c][r] # Word 'c' of this round key, byte 'r'
            expanded_keys.append(round_key_matrix)
        return expanded_keys

    ## AES Round Operations ##

    # AddRoundKey: XOR state with round key [cite: 93, 122]
    def _add_round_key(self, state, round_key_matrix):
        for r in range(4):
            for c in range(4):
                state[r][c] ^= round_key_matrix[r][c]
        return state # Modified in place

    # SubBytes: Substitute bytes using S-Box [cite: 93, 127]
    def _sub_bytes(self, state):
        for r in range(4):
            for c in range(4):
                state[r][c] = S_BOX[state[r][c]]
        return state

    def _inv_sub_bytes(self, state): # [cite: 141]
        for r in range(4):
            for c in range(4):
                state[r][c] = INV_S_BOX[state[r][c]]
        return state

    # ShiftRows: Cyclically shift rows [cite: 93, 131]
    def _shift_rows(self, state):
        # Row 0: no shift [cite: 133]
        # Row 1: 1-byte left shift [cite: 133]
        state[1] = state[1][1:] + state[1][:1]
        # Row 2: 2-byte left shift [cite: 133]
        state[2] = state[2][2:] + state[2][:2]
        # Row 3: 3-byte left shift [cite: 133]
        state[3] = state[3][3:] + state[3][:3]
        return state

    def _inv_shift_rows(self, state): # [cite: 141]
        # Row 0: no shift
        # Row 1: 1-byte right shift
        state[1] = state[1][3:] + state[1][:3] # or state[1][-1:] + state[1][:-1]
        # Row 2: 2-byte right shift
        state[2] = state[2][2:] + state[2][:2] # or state[2][-2:] + state[2][:-2]
        # Row 3: 3-byte right shift
        state[3] = state[3][1:] + state[3][:1] # or state[3][-3:] + state[3][:-3]
        return state

    # Galois Field multiplication helper (xtime: multiply by x, i.e., 0x02)
    def _xtime(self, a):
        if a & 0x80: # Check MSB
            return ((a << 1) ^ 0x1b) & 0xff
        else:
            return (a << 1) & 0xff

    def _gf_mul(self, a, b): # General GF multiplication if needed, or specific ones
        if b == 0x01: return a
        if b == 0x02: return self._xtime(a)
        if b == 0x03: return self._xtime(a) ^ a
        
        # For InvMixColumns multipliers
        xt_a = self._xtime(a)
        xt_xt_a = self._xtime(xt_a)
        xt_xt_xt_a = self._xtime(xt_xt_a)

        if b == 0x09: return xt_xt_xt_a ^ a
        if b == 0x0b: return xt_xt_xt_a ^ xt_a ^ a
        if b == 0x0d: return xt_xt_xt_a ^ xt_xt_a ^ a
        if b == 0x0e: return xt_xt_xt_a ^ xt_xt_a ^ xt_a
        
        # Fallback for other values (not strictly needed for AES fixed matrices)
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = (a & 0x80)
            a = (a << 1) & 0xff
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p


    # MixColumns: Mix columns using Galois Field multiplication [cite: 93, 136, 137]
    def _mix_columns(self, state):
        for c in range(4): # For each column
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c] # Current column values
            
            state[0][c] = self._gf_mul(s0, 0x02) ^ self._gf_mul(s1, 0x03) ^ self._gf_mul(s2, 0x01) ^ self._gf_mul(s3, 0x01)
            state[1][c] = self._gf_mul(s0, 0x01) ^ self._gf_mul(s1, 0x02) ^ self._gf_mul(s2, 0x03) ^ self._gf_mul(s3, 0x01)
            state[2][c] = self._gf_mul(s0, 0x01) ^ self._gf_mul(s1, 0x01) ^ self._gf_mul(s2, 0x02) ^ self._gf_mul(s3, 0x03)
            state[3][c] = self._gf_mul(s0, 0x03) ^ self._gf_mul(s1, 0x01) ^ self._gf_mul(s2, 0x01) ^ self._gf_mul(s3, 0x02)
        return state

    def _inv_mix_columns(self, state): # [cite: 141]
        for c in range(4):
            s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]

            state[0][c] = self._gf_mul(s0, 0x0e) ^ self._gf_mul(s1, 0x0b) ^ self._gf_mul(s2, 0x0d) ^ self._gf_mul(s3, 0x09)
            state[1][c] = self._gf_mul(s0, 0x09) ^ self._gf_mul(s1, 0x0e) ^ self._gf_mul(s2, 0x0b) ^ self._gf_mul(s3, 0x0d)
            state[2][c] = self._gf_mul(s0, 0x0d) ^ self._gf_mul(s1, 0x09) ^ self._gf_mul(s2, 0x0e) ^ self._gf_mul(s3, 0x0b)
            state[3][c] = self._gf_mul(s0, 0x0b) ^ self._gf_mul(s1, 0x0d) ^ self._gf_mul(s2, 0x09) ^ self._gf_mul(s3, 0x0e)
        return state

    ## AES Encryption and Decryption for a single block ##
    def _encrypt_block(self, plaintext_block_bytes):
        if len(plaintext_block_bytes) != 16:
            raise ValueError("Plaintext block must be 16 bytes.")

        state = self._bytes_to_matrix(plaintext_block_bytes)

        # Initial AddRoundKey [cite: 92, 93] (using round_keys[0])
        state = self._add_round_key(state, self.round_keys[0])

        # Main Rounds (1 to Nr-1) [cite: 91, 93]
        for r in range(1, self.Nr):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[r])
        
        # Final Round (Nr) - no MixColumns [cite: 125]
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[self.Nr])
        
        return self._matrix_to_bytes(state)

    def _decrypt_block(self, ciphertext_block_bytes): # [cite: 141]
        if len(ciphertext_block_bytes) != 16:
            raise ValueError("Ciphertext block must be 16 bytes.")

        state = self._bytes_to_matrix(ciphertext_block_bytes)

        # Initial AddRoundKey for decryption (uses last encryption round key) [cite: 141]
        state = self._add_round_key(state, self.round_keys[self.Nr])

        # Main Rounds for decryption (Nr-1 down to 1)
        for r in range(self.Nr - 1, 0, -1): # From 9 down to 1 for Nr=10
            state = self._inv_shift_rows(state) # [cite: 141]
            state = self._inv_sub_bytes(state) # [cite: 141]
            state = self._add_round_key(state, self.round_keys[r]) # [cite: 141]
            state = self._inv_mix_columns(state) # [cite: 141]
        
        # Final Round for decryption (undoes initial encryption operations)
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.round_keys[0])
        
        return self._matrix_to_bytes(state)

    ## Public API for encrypting/decrypting strings ##
    def encrypt(self, plaintext_str):
        plaintext_bytes = self._str_to_bytes(plaintext_str)
        padded_plaintext = self._pad(plaintext_bytes)
        
        ciphertext = b''
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            encrypted_block = self._encrypt_block(block)
            ciphertext += encrypted_block
        return ciphertext.hex() # Return as hex string

    def decrypt(self, ciphertext_hex_str):
        ciphertext_bytes = bytes.fromhex(ciphertext_hex_str)
        
        if len(ciphertext_bytes) % 16 != 0:
            raise ValueError("Ciphertext length must be a multiple of 16 bytes.")

        decrypted_padded_bytes = b''
        for i in range(0, len(ciphertext_bytes), 16):
            block = ciphertext_bytes[i:i+16]
            decrypted_block = self._decrypt_block(block)
            decrypted_padded_bytes += decrypted_block
        
        try:
            unpadded_bytes = self._unpad(decrypted_padded_bytes)
            return self._bytes_to_str(unpadded_bytes)
        except ValueError as e: # Catches padding errors
            print(f"Error during unpadding: {e}. Returning raw decrypted bytes (might be incorrect if padding was expected).")
            return self._bytes_to_str(decrypted_padded_bytes.rstrip(b'\x00')) # Simplistic attempt if not padded
