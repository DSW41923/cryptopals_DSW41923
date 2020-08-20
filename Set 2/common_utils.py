import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

def extend_key(text, desired_length):
    text_multiple = int(desired_length / len(text) + 1)
    key_string = text * text_multiple
    return key_string[:desired_length]

def split_by_length(string, length):

    return [string[i:i + length] for i in range(0, len(string), length)]

def padding_to_length(string, length):
    pad_length = length - len(string)
    if type(string) != bytes:
        string = string.encode()
    return string + bytes([pad_length] * pad_length)


def CBC_Encryptor(key, plaintext, iv):
    # Prepare encryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    # Make Plaintext Blocks
    ciphertext_result = []
    plaintext_blocks = split_by_length(plaintext, 16)
    for block_num, block in enumerate(plaintext_blocks):
        if len(block) < 16:
            block = padding_to_length(block, 16)

        if block_num == 0:
            pt = bytestrxor(block, iv)
        else:
            pt = bytestrxor(block, ciphertext_result[block_num - 1])
        ciphertext = encryptor.update(pt)
        ciphertext_result.append(ciphertext)
    return b''.join(ciphertext_result)


def CBC_Decryptor(key, ciphertext):
    # Prepare decryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    # Make Ciphertext Blocks
    plaintext_result = []
    ciphertext_blocks = split_by_length(ciphertext, 16)
    for block_num, block in enumerate(ciphertext_blocks[1:]):

        plaintext_block = decryptor.update(block)
        pt_block = bytestrxor(plaintext_block, ciphertext_blocks[block_num])
        plaintext_result.append(pt_block)

    return b''.join(plaintext_result)