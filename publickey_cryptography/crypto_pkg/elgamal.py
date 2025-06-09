# 파일 경로: crypto_pkg/elgamal.py
import random

def is_prime(n: int) -> bool:
    """n이 소수인지 여부를 판정하는 함수 (6k±1 최적화)"""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0 or n % 3 == 0: return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def is_primitive_root(g: int, p: int) -> bool:
    """(느리기 때문에 GUI에서 사용 비권장) g가 p의 원시근인지 판별하는 함수"""
    if not is_prime(p):
        return False
    required_set = set(range(1, p))
    actual_set = set(pow(g, i, p) for i in range(1, p))
    return required_set == actual_set

def generate_keys(p: int, g: int) -> tuple:
    # self.is_prime이 아니라 is_prime을 직접 호출
    if not is_prime(p):
        return (False, f"{p}는 소수가 아닙니다.")
    
    d = random.randrange(2, p - 1)
    e = pow(g, d, p)
    
    public_key = (p, g, e)
    private_key = d
    
    return (True, {'public_key': public_key, 'private_key': private_key})

def encrypt(m_int: int, public_key: tuple) -> tuple:
    p, g, e = public_key
    
    if m_int >= p:
        raise ValueError("메시지가 소수 P보다 큽니다. 더 큰 키(P)를 사용하세요.")

    k = random.randrange(2, p - 1)
    y1 = pow(g, k, p)
    y2 = (m_int * pow(e, k, p)) % p
    
    return (y1, y2)

def decrypt(ciphertext: tuple, p: int, private_key: int) -> int:
    y1, y2 = ciphertext
    d = private_key
    
    s = pow(y1, d, p)
    s_inv = pow(s, -1, p)
    m_int = (y2 * s_inv) % p
    
    return m_int