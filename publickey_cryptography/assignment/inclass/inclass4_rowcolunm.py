import math

def row_column_transposition_encrypt(plaintext, key):
    # 1. 사전 정리
    plaintext = ''.join(plaintext.upper().split())  # 공백 제거, 대문자
    cols = len(key)
    rows = math.ceil(len(plaintext) / cols)

    # 2. 평문 보충
    padded_len = rows * cols
    if len(plaintext) < padded_len:
        plaintext += 'X' * (padded_len - len(plaintext))

    # 3. 매트릭스 만들기
    matrix = []
    idx = 0
    for _ in range(rows):
        matrix.append([char for char in plaintext[idx:idx + cols]])
        idx += cols

    # 4. 열 순서 정렬: key → 열 번호 매핑 후 인덱스 순 정렬
    sorted_key = sorted((num, i) for i, num in enumerate(key))
    col_order = [i for _, i in sorted_key]

    # 5. 암호화
    ciphertext = ''
    for col in col_order:
        for row in range(rows):
            ciphertext += matrix[row][col]
    return ciphertext

import math

def row_column_transposition_decrypt(ciphertext, key):
    cols = len(key)
    rows = math.ceil(len(ciphertext) / cols)

    # 정렬된 키 기준으로 각 열이 몇 번째 열인지 확인
    sorted_key = sorted((num, i) for i, num in enumerate(key))
    col_order = [i for _, i in sorted_key]

    # 각 열의 문자 개수 계산
    total_chars = len(ciphertext)
    col_lengths = [rows] * cols

    # 열 데이터 나누기
    matrix_cols = [''] * cols
    idx = 0
    for k in col_order:
        matrix_cols[k] = ciphertext[idx:idx + col_lengths[k]]
        idx += col_lengths[k]

    # 열 데이터 기반으로 행 단위로 재구성
    matrix = []
    for r in range(rows):
        row = [matrix_cols[c][r] for c in range(cols)]
        matrix.append(row)

    # 행 기준으로 평문 복원
    plaintext = ''.join(''.join(row) for row in matrix)
    return plaintext

text = input("plaintext:")
key = list(map(int, input("key:").split()))
frequency = int(input("frequency:"))  # 이 경우는 행 수가 아니라 반복 또는 기본 설정 의미로 보임 (사용 안 함)


for _ in range(frequency):
    text = row_column_transposition_encrypt(text, key)

print("Ciphertext:", text)

for _ in range(frequency):
    text = row_column_transposition_decrypt(text, key)

print("Plaintext:", text)