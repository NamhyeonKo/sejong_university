import string
import random

#   Substitution Cipher encrypto & decrypto
#   It could not be made into upper and lowercase cases, so it was unified into lowercase and printed out.
def substitution_cipher(text, key, decrypt=False) -> str:
    #   making lower alphabet character list
    alphabet = string.ascii_lowercase
    #   grouping alphabet list and random key accordingly and matching each letter
    key_map = dict(zip(alphabet, key.lower())) if not decrypt else dict(zip(key.lower(), alphabet))
    return "".join(key_map.get(char, char) for char in text.lower())

#   making new random key when user choose substitution cipher
def generate_random_key() -> str:
    random_key = list(string.ascii_lowercase)
    random.shuffle(random_key)
    return ''.join(random_key)