#knapsack 암호 구현

# 서로소 찾기 위해 필요
import random

def gcd(a,b):
    if a < b:
        a,b = b,a
    while True:
        q = a // b
        r = a % b
        a = b
        b = r
        if b==0:
            break
    return a

def extended_gcd(a,b):
    if a < b:
        a,b = b,a
    r1 = a
    r2 = b
    s1 = 1
    s2 = 0
    t1 = 0
    t2 = 1
    
    while(r2 > 0): 
        q = r1 // r2
        r = r1 - q * r2
        r1 , r2 = r2 , r
        
        s = s1 - q * s2
        s1 , s2 = s2 , s
        
        t = t1 - q * t2
        t1 , t2 = t2 , t
    return s1

def find_disjoint(m):
    while True:
        i = random.randint(2,m)
        if gcd(i,m) == 1:
            return i

#매개 변수 n을 취하여 초증가 배낭 요소 a = [a_1, a_2, ... , a_n] 및 m > 2 * a_n과 같은 모듈러스 m의 목록 반환
def generate_superinc_knapsack(n):
    a = [0] * n
    k = 3
    for i in range(n):
        a[i] = k
        k  = k * 2 + 1
    return a, a[n-1] * 2 + 1

#매개 변수 n을 사용하여 개인 키 sk와 공용 키 pk를 반환 -> generate_superinc_knapsack 알고리즘 실행
def knapsack_genkey(n):
    a , m = generate_superinc_knapsack(n)
    print("a = {}".format(a))
    w = find_disjoint(m)
    wi = extended_gcd(w,m)

    pk = [0] * n
    b = [0] * n

    for i in range(n):
        b[i] = (w * a[i]) % m
        pk[i] = b[i]
    
    pk.append(m)
    sk = wi

    print("pk = {}".format(pk))
    print("sk = {}".format(sk))
    return sk, pk

# 정수 메시지 p와 공개 키 pk를 가져와서 정수 암호문 c를 출력 - 암호화 프로세스에서 p를 이진 값으로 변환
def knapsack_encrypt(p,pk):
    M = format(p,'b')
    
    print(M)
    print(len(M))
    string_M = str(M)

    s = 0

    for i in range(len(M)):
        s = s + (pk[i] * int(string_M[i]))
    c = s % pk[len(pk)-1]

    print(c)
    return c

# 정수 암호문 c와 개인 키 sk를 가져와서 정수 메시지 p를 출력
def knapsack_decrypt(c,sk):
    p = c * sk
    return p

n = {10,20,30,40,50}
for i in n:
    sk, pk = knapsack_genkey(i)
    p = 123
    c = knapsack_encrypt(p,pk)
    print(c)
