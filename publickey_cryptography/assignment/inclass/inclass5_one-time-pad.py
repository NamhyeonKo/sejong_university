def char_to_bin(c):
    return format(ord(c), '08b')

def xor_bin(a, b):
    return format(int(a, 2) ^ int(b, 2), '08b')

plaintext = "LOVECRYPTOGRAPHY"
key = "GOODAPPRECIATION"

# 공백 제거 (없음) / key 길이 맞춰져 있음
print("Plaintext :", plaintext)
print("Key       :", key)
print("\nencryption process (XOR - ASCII):\n")

cipher_bin_list = []
cipher_ascii_list = []
cipher_char_list = []

for i in range(len(plaintext)):
    pt_char = plaintext[i]
    key_char = key[i]

    pt_ascii = ord(pt_char)
    key_ascii = ord(key_char)

    pt_bin = format(pt_ascii, '08b')
    key_bin = format(key_ascii, '08b')

    xor_ascii = pt_ascii ^ key_ascii
    xor_bin_val = format(xor_ascii, '08b')
    xor_char = chr(xor_ascii)

    cipher_ascii_list.append(xor_ascii)
    cipher_bin_list.append(xor_bin_val)
    cipher_char_list.append(xor_char)

    print(f"[{i+1}] '{pt_char}' ({pt_ascii}, {pt_bin}) ⊕ '{key_char}' ({key_ascii}, {key_bin}) → {xor_ascii}, {xor_bin_val} → '{repr(xor_char)}'")

print("\nfinal encryption (2진수):")
print(' '.join(cipher_bin_list))

print("\nfinal encryption (char):")
print(''.join(cipher_char_list))

# 복호화
print("\ndecryption (encryption ⊕ key):\n")

recovered_text = []

for i in range(len(cipher_ascii_list)):
    xor_val = cipher_ascii_list[i]
    key_ascii = ord(key[i])

    recovered_ascii = xor_val ^ key_ascii
    recovered_bin = format(recovered_ascii, '08b')
    recovered_char = chr(recovered_ascii)
    recovered_text.append(recovered_char)

    print(f"[{i+1}] {xor_val} ({format(xor_val, '08b')}) ⊕ {key_ascii} ({format(key_ascii, '08b')}) → {recovered_ascii}, {recovered_bin} → '{recovered_char}'")

print("\n result:")
print(''.join(recovered_text))
