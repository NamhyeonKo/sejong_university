from math import gcd

# 소수 판별 함수
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5)+1):
        if n % i == 0:
            return False
    return True

# 약수 구하기
def get_divisors(n):
    return [i for i in range(1, n+1) if n % i == 0]

# 서로소 판단
def is_coprime(a, b):
    return gcd(a, b) == 1

input_str = input("Enter a set of numbers (e.g. 2 5 10): ")
numbers = list(map(int, input_str.strip().split()))

prime_numbers = []

print("\n=== Number Analysis ===")
for num in numbers:
    divisors = get_divisors(num)
    if is_prime(num):
        prime_numbers.append(num)

print("\n=== Prime Numbers ===")
if prime_numbers:
    print("Prime numbers:", prime_numbers)
else:
    print("No prime numbers found.")

print("\n=== Co-Prime Pairs ===")
found = False
for i in range(len(numbers)):
    for j in range(i+1, len(numbers)):
        a, b = numbers[i], numbers[j]
        if is_coprime(a, b):
            print(f"({a},{b})",end=' ')
            found = True
if not found:
    print("No co-prime pairs found.")
