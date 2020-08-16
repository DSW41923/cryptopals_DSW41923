import string

char_freq = {'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881,
'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124,
'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}

def bytestrxor(a, b):
    return bytes([x ^ y for (x, y) in zip(a, b)])

def evaluate_palintext(plaintext):
    point = 0
    for byte in plaintext:
        if byte >= 128:
            return -1

        char = byte.to_bytes(1, 'big').decode()

        # Improved with frequency
        point += char_freq.get(char.lower(), 0)

    return point

def generate_key(text, desired_length):
    text_multiple = int(desired_length / len(text) + 1)
    key_string = text * text_multiple
    return key_string[:desired_length]

def split_by_length(string, length):

    return [string[i:i + length] for i in range(0, len(string), length)]