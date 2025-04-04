import math #use sqrt, ceil

# By using the division method
def factoring_simple(n):
    arr = []
    for i in range(2, int(math.sqrt(n))+1,1):
        while n % i ==0:
            arr.append(i)
            n = n // i
    if n > 2:
        arr.append(n)
    return list(set(arr))

def factoring_fermat(n):
    x = math.ceil(math.sqrt(n))
    y = x**2 - n
    while not math.sqrt(y).is_integer():
        x += 1
        y = x**2 - n
    return int(x + math.sqrt(y)), int(x - math.sqrt(y))

#print example of factoring_simple
print(factoring_simple(11))
print(factoring_simple(100))
print(factoring_simple(12345))
print(factoring_simple(1000001))
print(factoring_simple(2**16))

#print example of factoring_fermat
print(factoring_fermat(15))
print(factoring_fermat(119))
print(factoring_fermat(187))
print(factoring_fermat(2987))
print(factoring_fermat(6750311))