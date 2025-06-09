# xa, ya random
# p, g 입력값
import random

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

def is_prime(n: int) -> bool:
    """n이 소수인지 여부를 판정하는 함수 (6k±1 최적화)"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def power(base, exp, mod):
    return pow(base, exp, mod)

p = int(input("prime (p) : "))

if not is_prime(p):
    print("it is not prime")
else:
    g = int(input("generate (g) : "))

    # test primitive root
    test_p = []
    for i in range(1, p):
        test_p.append((g**i)%p)
    set_test = set(test_p)
    if len(set_test) != len(test_p):
        print("it is not the primitive root!!!!")
    else:
        xa = random.randrange(1,p)
        ya = random.randrange(1,p)

        a = power(g, xa, p)
        b = power(g, ya, p)

        sa = power(b, xa, p)
        sb = power(a, ya, p)

        if sa == sb:
            print("generated S is correct")

        print(f"a : {a}, b : {b}, s : {sa}")

        plaintext = input("input plaintext : ")

        print("cipher text : ",shift_cipher(plaintext, sa))