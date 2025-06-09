# crypto_pkg/diffie_hellman.py
import random
from Crypto.Util import number

#   - p: pycryptodome 라이브러리를 이용해 효율적으로 안전한 소수를 생성합니다.
#   - g: 2를 생성자(원시근)로 사용합니다.
def generate_dh_params(bits):
    p = number.getPrime(bits)
    g = 2
    return p, g

#   - private_key: 1과 p-2 사이의 임의의 정수
#   - public_key: (g ^ private_key) mod p
def generate_person_keys(p, g):
    private_key = random.randrange(2, p - 1)
    public_key = pow(g, private_key, p)
    return private_key, public_key

#   - shared_secret: (their_public_key ^ my_private_key) mod p
def generate_shared_secret(their_public_key, my_private_key, p):
    shared_secret = pow(their_public_key, my_private_key, p)
    return shared_secret