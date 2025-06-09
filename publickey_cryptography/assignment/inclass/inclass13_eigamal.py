# xa, ya random
# p, g 입력값
import sys
import random
import math

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

def is_coprime(num1, num2) -> bool:
    if math.gcd(num1, num2) == 1:
        return True
    else:
        return False

p = int(input("prime (p) : "))

# test prime number
if not is_prime(p):
    print("it is not prime")
    sys.exit()

g = int(input("generate (g) : "))

test_p = []
for i in range(1, p):
    test_p.append((g**i)%p)
set_test = set(test_p)

# test primitive root
if len(set_test) != len(test_p):
    print("it is not the primitive root!!!!")
    sys.exit()

# test co-prime
if not is_coprime(p,g):
    print("it is not coprime")
    sys.exit()

# this is alice's primate-key
d = random.randrange(1,p-1)
print("d : ",d)

# this is alice's public-key
e = (g ** d) % p
print("e : ",e)

m = int(input("plain text : "))
k = random.randrange(1,p-1)

print("m : ",m)
print("k : ",k)

y1 = (g ** k) % p
y2 = (m * (e ** k)) % p

print("y1 : ",y1)
print("y2 : ",y2)

m2 = y2 * ((y1 ** d) ** -1)
print("decrypted m : ", m2)