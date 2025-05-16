#   Vigenere Cipher encrypto & decrypto
def vigenere_cipher(text, key, decrypt=False):
    result = []
    key = key.lower()
    key_len = len(key)
    
    #   using key_index to start key's first letter when new word starts
    key_index = 0
    
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % key_len]) - ord('a')
            shift = -shift if decrypt else shift

            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + shift) % 26 + base))
        
            key_index += 1
        else:
            result.append(char)
            if char == " ":
                key_index = 0
    
    return "".join(result)