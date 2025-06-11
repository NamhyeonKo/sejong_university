import random
import os

def is_prime(n: int, k: int = 40) -> bool:
    """
    밀러-라빈 소수 판별법을 사용하여 n이 소수일 가능성이 높은지 검사합니다.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
            
        is_composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                is_composite = False
                break
        
        if is_composite:
            return False

    return True

def gcd(a, b):
    """
    유클리드 호제법을 이용해 두 수의 최대공약수를 구합니다.
    """
    while b:
        a, b = b, a % b
    return a

def generate_rsa_keys(bits: int = 256):
    """
    주어진 비트 수에 맞는 RSA 공개키와 개인키를 생성합니다.
    """
    if bits < 64:
        raise ValueError("키 비트 크기가 너무 작습니다. p와 q는 각각 최소 64비트 이상이어야 합니다.")

    p = q = 0
    while not is_prime(p):
        p = random.getrandbits(bits)
    while not is_prime(q) or p == q:
        q = random.getrandbits(bits)

    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    e = 65537
    if gcd(e, phi_n) != 1:
        e = random.randrange(3, phi_n, 2)
        while gcd(e, phi_n) != 1:
            e += 2

    # --- 핵심 버그 수정 ---
    # 이전에 제가 직접 작성했던 mod_inverse 함수에 버그가 있었습니다.
    # Python 3.8 이상에서 제공하는 내장 함수 pow(e, -1, phi_n)를 사용하는 것이
    # 가장 정확하고 안전하며 효율적입니다.
    try:
        d = pow(e, -1, phi_n)
    except TypeError:
        # pow(e, -1, m)는 Python 3.8부터 지원됩니다.
        raise RuntimeError("이 코드를 실행하려면 Python 3.8 이상이 필요합니다.")
    # --- 수정 끝 ---
    
    public_key = (e, n)
    private_key = (d, n)
    
    return public_key, private_key, p, q

def rsa_encrypt(public_key: tuple, message: str) -> int:
    """
    RSA 공개키와 PKCS#1 v1.5 패딩을 사용하여 메시지를 암호화합니다.
    """
    e, n = public_key
    key_size_bytes = (n.bit_length() + 7) // 8
    
    message_bytes = message.encode('utf-8')
    
    if len(message_bytes) > key_size_bytes - 11:
        raise ValueError(f"메시지가 너무 깁니다. 최대 {key_size_bytes - 11}바이트까지 가능합니다.")
        
    ps_len = key_size_bytes - len(message_bytes) - 3
    
    padding_string = b''
    while len(padding_string) < ps_len:
        rand_byte = os.urandom(1)
        if rand_byte != b'\x00':
            padding_string += rand_byte

    padded_message = b'\x00\x02' + padding_string + b'\x00' + message_bytes
    
    m_int = int.from_bytes(padded_message, 'big')
    
    ciphertext = pow(m_int, e, n)
    return ciphertext

def rsa_decrypt(private_key: tuple, ciphertext: int) -> str:
    """
    RSA 개인키로 암호문을 복호화하고 패딩을 제거합니다.
    """
    d, n = private_key
    key_size_bytes = (n.bit_length() + 7) // 8

    m_int = pow(ciphertext, d, n)
    padded_message = m_int.to_bytes(key_size_bytes, 'big')
    
    if not padded_message.startswith(b'\x00\x02'):
        raise ValueError("복호화 오류: 잘못된 패딩 형식입니다 (시작 바이트 불일치).")

    try:
        separator_index = padded_message.index(b'\x00', 2)
    except ValueError:
        raise ValueError("복호화 오류: 패딩에서 메시지 구분자를 찾을 수 없습니다.")
        
    message_bytes = padded_message[separator_index + 1:]
    
    return message_bytes.decode('utf-8')