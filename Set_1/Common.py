import string

def bytestrxor(a, b):
    return bytes([x ^ y for (x, y) in zip(a, b)])

def evaluate_palintext(plaintext):
    point = 0
    for byte in plaintext:
        if byte >= 128:
            return -1

        char = byte.to_bytes(1, 'big').decode()

        if char in string.printable:
            point += 1

        if char in string.ascii_letters:
            point += 1

        if char == ' ':
            point += 1

    return point