from random import choice
from math import sqrt

def is_prime(n):
    for i in range(2,int(sqrt(n))+1):
        if n % i == 0:
            return 0
    return 1


def generate_all_primes(n):
    for i in range(2,n+1):
        if is_prime(i) == 1:
            print(i,end=" ")
    print()

def generate_random_prime(n,m):
    a = []
    for i in range(n,m+1):
        if is_prime(i) == 1:
            a.append(i)
    print(choice(a))


print(is_prime(11))
print(is_prime(253))
print(is_prime(65537))

generate_all_primes(50)
generate_all_primes(100)
generate_all_primes(1000)

generate_random_prime(2, 11)
generate_random_prime(100, 200)
generate_random_prime(1000, 2000)
