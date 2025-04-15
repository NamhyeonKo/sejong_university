plain_text = 'ISOLICOMOHISOLICOMOHLRWVTASELESL'

def rail_fence_encrypt(plaintext, rails):
    fence = ['' for _ in range(rails)]
    rail = 0
    direction = 1

    for char in plaintext:
        fence[rail] += char
        rail += direction

        if rail == 0 or rail == rails - 1:
            direction *= -1

    return ''.join(fence)


def rail_fence_decrypt(ciphertext, rails):
    # 지그재그 패턴 생성
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    pattern = pattern * (len(ciphertext) // len(pattern) + 1)
    pattern = pattern[:len(ciphertext)]

    # 각 레일마다 문자의 개수 계산
    rail_lengths = [pattern.count(r) for r in range(rails)]

    # 각 레일에 문자 분배
    rails_text = []
    idx = 0
    for length in rail_lengths:
        rails_text.append(ciphertext[idx:idx+length])
        idx += length

    # 지그재그 순서에 따라 평문 재구성
    result = ''
    rail_indices = [0] * rails
    for r in pattern:
        result += rails_text[r][rail_indices[r]]
        rail_indices[r] += 1

    return result