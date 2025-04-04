def lucas_lehmer_test(p):
    # it tests whether the Mersenne number M_p = 2^p - 1 is prime or not where p is a prime by using the Lucas-Lehmer test. It outputs 1 if it is prime or 0 otherwise.
    if p == 1:
        return 0
    elif p == 2:
        return 1
    M_p = 2 ** p - 1
    s = 4
    for i in range(p-2):
        s = (s * s - 2) % M_p
    return int(s == 0)

def generate_all_primes(n):
    for i in range(2, n + 1):
        if lucas_lehmer_test(i) == 1:
            print(2 ** i - 1)
    print()

def find_mersenne_primes(max):
    # it prints all Mersenne primes from 3 to the Mersenne number M_{max} by using the lucas_lehmer_test function and generate_all_primes function
    generate_all_primes(max)

print('lucas_lehmer_test')
print(lucas_lehmer_test(3))
print(lucas_lehmer_test(17))
print(lucas_lehmer_test(31))
print(lucas_lehmer_test(521))
print(lucas_lehmer_test(9689))
print(lucas_lehmer_test(9697))
print('find_mersenne_primes')
find_mersenne_primes(5000)