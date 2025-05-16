# crypto_pkg/playfair.py
from collections import Counter

def input_in_board(letters, board):
    for l in letters:
        if l == 'j': l = 'i'
        if l not in board:
            board.append(l)

def make_playfair_key_board(key: str) -> list[str]:
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    board = []
    input_in_board(key.lower(), board)
    input_in_board(alphabet, board)
    return board

def preprocess_text(plain: str) -> str:
    result = []
    i = 0
    while i < len(plain):
        a = plain[i]
        b = plain[i+1] if i+1 < len(plain) else 'x'
        result.append(a)
        if a == b:
            result.append('x')
        else:
            result.append(b)
            i += 1
        i += 1
    if len(result) % 2:
        result.append('x')
    return "".join(result)

def _pos(board: list[str], ch: str) -> tuple[int,int]:
    idx = board.index(ch)
    return divmod(idx, 5)

def playfair_cipher(text: str, key: str, encrypt: bool=True) -> str:
    board = make_playfair_key_board(key)
    txt   = preprocess_text(text.lower())
    shift = 1 if encrypt else -1
    out = []
    for i in range(0, len(txt), 2):
        a, b = txt[i], txt[i+1]
        ax, ay = _pos(board, a)
        bx, by = _pos(board, b)
        if ax == bx:
            out += [ board[ax*5 + (ay+shift) % 5],
                     board[bx*5 + (by+shift) % 5] ]
        elif ay == by:
            out += [ board[((ax+shift)%5)*5 + ay],
                     board[((bx+shift)%5)*5 + by] ]
        else:
            out += [ board[ ax*5 + by ], board[ bx*5 + ay ] ]
    res = "".join(out)
    return res if encrypt else res.replace("x","")