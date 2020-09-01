import sys
import getopt
import binascii
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from challenge_02 import bytestrxor
from challenge_08 import split_by_length


def CTR_cryptor(text, key, nonce):

    # Prepare encryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    # Make Blocks
    result_blocks = []
    text_blocks = split_by_length(text, 16)
    for block_num, block in enumerate(text_blocks):
        counter = nonce + block_num.to_bytes(8, byteorder='little')
        ctr_key = encryptor.update(counter)
        block_ciphertext = bytestrxor(block, ctr_key)
        result_blocks.append(block_ciphertext)
    return b''.join(result_blocks)


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_18.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_18.py [-h | --help]')
            print('Challenge 18: Implement CTR, the stream cipher mode')
            sys.exit()

    nonce = bytes([0] * 8)
    key = b"YELLOW SUBMARINE"
    ciphertext = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    decoded_ciphertext = base64.b64decode(ciphertext)
    plaintext = CTR_cryptor(decoded_ciphertext, key, nonce)
    print(b"Plaintext is : " + plaintext)


if __name__ == "__main__":
    main(sys.argv[1:])