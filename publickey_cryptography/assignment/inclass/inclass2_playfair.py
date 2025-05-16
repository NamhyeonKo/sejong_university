# function to input letters in board
def input_in_board(letters, board):
    # input playfair key in board but once in a while
    for l in letters:
        if l == 'j':  # replace 'j' with 'i'
            l = 'i'
        if l not in board:
            board.append(l)

# function to make playfair key board
def make_playfair_key_board(playfair_key):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    board = []

    input_in_board(playfair_key, board)
    input_in_board(alphabet, board)

    return board

# function to preprocess plain text for Playfair cipher
def preprocess_text(plain_text):
    result = []
    i = 0
    while i < len(plain_text):
        a = plain_text[i]
        b = plain_text[i + 1] if i + 1 < len(plain_text) else 'x'

        # when the pair letters are the same, put an 'x' between
        if a == b:
            result.append(a)
            result.append('x')
        else:
            result.append(a)
            result.append(b)
            i += 1
        i += 1

    # when last letter pair is odd, put an 'x' at the end
    if len(result) % 2 == 1:
        result.append('x')

    return "".join(result)

# function to get position of a character in the board
def get_position(board, char):
    idx = board.index(char)
    return idx // 5, idx % 5  # row, column

# function to encrypt plain text using playfair cipher
def playfair_cipher(plain_text, board):
    text = preprocess_text(plain_text)
    result = []

    for i in range(0, len(text), 2):
        a_x, a_y = get_position(board, text[i])
        b_x, b_y = get_position(board, text[i + 1])

        # if both of the pair letters are the same row, move one space to the right side
        if a_x == b_x:
            result.append(board[a_x * 5 + (a_y + 1) % 5])
            result.append(board[b_x * 5 + (b_y + 1) % 5])
        # if both of the pair letters are the same column, move one space down
        elif a_y == b_y:
            result.append(board[((a_x + 1) % 5) * 5 + a_y])
            result.append(board[((b_x + 1) % 5) * 5 + b_y])
        # if both of the pair letters make rectangle, column switch not move row
        else:
            result.append(board[a_x * 5 + b_y])
            result.append(board[b_x * 5 + a_y])

    return "".join(result)

#   main code
plain_text = input("plain text : ")
playfair_key = input("playfair key : ")

board = make_playfair_key_board(playfair_key)
cipher_text = playfair_cipher(plain_text, board)

print('result : '+ cipher_text)