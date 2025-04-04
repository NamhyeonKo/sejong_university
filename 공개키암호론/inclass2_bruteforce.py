alphabet = 'abcdefghijklmnopqrstuvwxyz'

cipher = input()
cipher.lower()

for i in range(26):
    result = str(i)+') '
    for c in cipher:
        result += chr(((ord(c) - ord('a')) + i )% 26 + ord('a'))
    print(result)