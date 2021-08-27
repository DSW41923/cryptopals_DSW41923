import sys
import getopt
import binascii
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from challenge_02 import bytestrxor
from challenge_08 import split_by_length
from challenge_09 import padding_to_length


def cbc_encryptor(key, plaintext, iv):
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
    return iv + b''.join(ciphertext_result)


def cbc_decryptor(key, ciphertext):
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


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "h:", ["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_10.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_10.py [-h | --help]')
            print('Challenge 10: Implement CBC mode')
            sys.exit()
    try:
        original_ciphertext = ''
        for line in open('input_10.txt', 'r'):
            original_ciphertext += line
    except FileNotFoundError as e:
        print(repr(e))
        sys.exit(2)
    else:
        iv = bytes([0] * 16)
        key_text = "YELLOW SUBMARINE"
        try:
            key = key_text.encode()
            ciphertext = iv + base64.b64decode(original_ciphertext.encode())
        except binascii.Error as e:
            print("Decoding Error: " + str(e))
            sys.exit(2)
        else:
            plaintext = cbc_decryptor(key, ciphertext)
            print("Plaintext is: " + plaintext.decode())


if __name__ == "__main__":
    main(sys.argv[1:])
