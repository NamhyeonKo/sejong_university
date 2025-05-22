# --- DES Tables ---
# PC-1 table (64 bits to 56)
pc1_table = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
    ]
# shifts of each rounds (round 1 ~ round 16)
round_shifts = [
    0,1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
    ]
# PC-2 table (56 bits to 48)
pc2_table = [
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
    ]
# IP table
ip_table = [
    58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7
    ]
# e bit selection table
e_bit_table = [
    32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1
    ]
# s_boxes
s_boxes = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]
# round_algorithm permutation table
p_box_table = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]
# ip inverse table
ip_inverse_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# --- Helper Functions ---
def hex_to_bin(hex_str, pad_to_bits=64):
    return bin(int(hex_str, 16))[2:].zfill(pad_to_bits)

def bin_to_hex(bin_str):
    return hex(int(bin_str, 2))[2:].upper().zfill(16) # Ensure 16 hex chars for 64 bits

def permute(input_str, table):
    return ''.join([input_str[pos - 1] for pos in table])

def left_shift(value, shifts):
    width = len(value)
    return value[shifts:] + value[:shifts]

# --- Phase 1: Key Schedule ---

def phase1_A_permutation(k_hex: str) -> tuple[str, str, str]:
    # Phase 1-A: Permutation
    bin_k = hex_to_bin(k_hex, 64)
    k_plus = permute(bin_k, pc1_table)
    c0 = k_plus[:28]
    d0 = k_plus[28:]
    return c0, d0, bin_k

def generate_subkeys(k_hex: str) -> tuple[list[str], list[str], list[str], str]:
    c = [''] * 17
    d = [''] * 17
    keys = [''] * 17

    c[0], d[0], initial_k_bin = phase1_A_permutation(k_hex)

    for i in range(1, 17):
        # Phase 1-B: Using Left Shift Table
        shifts = round_shifts[i]
        c[i] = left_shift(c[i-1], shifts)
        d[i] = left_shift(d[i-1], shifts)

        # Phase 1-C: Applying PC-2 (56 bits to 48)
        keys[i] = permute(c[i] + d[i], pc2_table)
    return keys[1:], c, d, initial_k_bin

# --- Phase 2: Feistel Network Rounds ---
def phase2_A_message_permutation(m_bin: str) -> tuple[str, str]:
    # Phase 2-A: Message Permutation (IP Table)
    ip_output = permute(m_bin, ip_table)
    return ip_output[:32], ip_output[32:] # L0, R0

def expansion_32bit_to_48bit(r_block: str) -> str:
    # Phase 2-B-1: Round Algorithm (Expansion / E bit Selection table)
    return permute(r_block, e_bit_table)

def s_box_substitution(s_input_48bit: str) -> tuple[str, str]:
    # Phase 2-B-2: Round Algorithm
    s_output_32bit = ''
    s_box_decimal_values = []
    for i in range(8):
        six_bit_block = s_input_48bit[6*i : 6*i+6]
        row = int(six_bit_block[0] + six_bit_block[5], 2)
        col = int(six_bit_block[1:5], 2)

        value = s_boxes[i][row][col]
        s_box_decimal_values.append(str(value))
        s_output_32bit += bin(value)[2:].zfill(4)
    return s_output_32bit, " ".join(s_box_decimal_values)

def p_box_permutation(s_box_output_32bit: str) -> str:
    # Phase 2-B-3: Round Algorithm
    return permute(s_box_output_32bit, p_box_table)

def feistel_round(L: str, R: str, subkey: str, round_num: int, log_func) -> tuple[str, str, str, str, str, str]:
    new_L = R

    # Calculate f(R, K)
    expanded_R = expansion_32bit_to_48bit(R)
    xor_result = bin(int(expanded_R, 2) ^ int(subkey, 2))[2:].zfill(48)

    s_box_output_bin, s_box_decimal_str = s_box_substitution(xor_result)
    p_box_output = p_box_permutation(s_box_output_bin)

    new_R = bin(int(L, 2) ^ int(p_box_output, 2))[2:].zfill(32)

    log_func(f"    L_{round_num-1} = {L}")
    log_func(f"    R_{round_num-1} = {R}")
    log_func(f"    K_{round_num} = {subkey}")
    log_func(f"    Expanded R = {expanded_R}")
    log_func(f"    (E(R) XOR K) = {xor_result}")
    log_func(f"    S-box results (decimal): {s_box_decimal_str}")
    log_func(f"    S-box output (binary) = {s_box_output_bin}")
    log_func(f"    P-box output = {p_box_output}")
    log_func(f"    New L_{round_num} (R_{round_num-1}) = {new_L}")
    log_func(f"    New R_{round_num} (L_{round_num-1} XOR P(S(E(R) XOR K))) = {new_R}")

    return new_L, new_R, expanded_R, xor_result, s_box_output_bin, p_box_output # Return intermediates for GUI

# --- Main DES Operations ---
def des_operation(input_text_hex: str, keys: list[str], mode: str, log_func) -> dict:
    log_func(f"\n--- {mode.upper()} Process ---")
    input_text_bin = hex_to_bin(input_text_hex, 64)
    log_func(f"Input ({mode} hex) = {input_text_hex}")
    log_func(f"Input ({mode} binary) = {input_text_bin}\n")

    # 1. Initial Permutation (IP)
    L, R = phase2_A_message_permutation(input_text_bin)
    log_func(f"Initial Permutation (IP) output:")
    log_func(f"  L0 = {L}")
    log_func(f"  R0 = {R}\n")

    # Store intermediates for GUI display
    l1_val, r1_val, s_box_out_r1, p_box_out_r1 = "", "", "", ""

    # 2. 16 Rounds of Feistel Cipher
    current_keys = keys if mode == "encrypt" else keys[::-1] # K1-K16 for encrypt, K16-K1 for decrypt

    for i in range(1, 17):
        log_func(f"\n--- {mode.upper()} Round {i} ---")
        current_L, current_R, _, _, current_s_box_out, current_p_box_out = feistel_round(L, R, current_keys[i-1], i, log_func)
        L = current_L
        R = current_R

        if i == 1: # Capture L1 and R1 and S-box, P-box output of first round
            l1_val = L
            r1_val = R
            s_box_out_r1 = current_s_box_out
            p_box_out_r1 = current_p_box_out

    # 3. Swap L and R (after 16 rounds, before final IP inverse)
    preoutput = R + L
    log_func(f"\nPreoutput (R16L16 for Enc/R0L0 for Dec) = {preoutput}")

    # --- Phase 3: Final step ---
    # 4. Final Permutation (IP Inverse)
    final_output_bin = permute(preoutput, ip_inverse_table)

    return {
        'final_output_bin': final_output_bin,
        'l1_val': l1_val,
        'r1_val': r1_val,
        's_box_out_r1': s_box_out_r1,
        'p_box_out_r1': p_box_out_r1
    }