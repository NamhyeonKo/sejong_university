# excercies L -> a, b / 소수인 modulo 을 입력하면 원시근 표 출력

modulo = int(input("modulo (is prime) : "))

array = [[] for i in range(modulo)]

for a in range(modulo):
    if a == 0:
        print("b",end = ' ')
        for i in range(1, modulo):
            print(f"b{i}",end = ' ')
        print()
    else:
        for i in range(1,modulo):
            array[a].append((a**i) % modulo)

for i in range(1, modulo):
    print(i, end = ' : ')
    print(array[i])