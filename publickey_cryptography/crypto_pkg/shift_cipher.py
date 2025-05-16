#   Shift Cipher encrypto & decrypto
def shift_cipher(text, shift, decrypt=False) -> str:
    #   decrypto is reverse encrypto!
    if decrypt:
        shift = -shift
    result = ""

    for char in text:
        #   check letter is alphabet, otherwise do not change letter
        if char.isalpha():
            #   determine capital letter and small letter
            #   shift base is an Ascii code of basic character
            shift_base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result