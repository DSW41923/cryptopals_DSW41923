import sys
import getopt
import binascii
import base64
import secrets

from challenge_02 import bytestrxor
from challenge_18 import CTR_cryptor


NONCE = bytes([0] * 8)
CTR_KEY = secrets.token_bytes(16)


def edit(ciphertext, key, offset, newtext):
    plaintext = CTR_cryptor(ciphertext, key, NONCE)
    new_plaintext = plaintext[:offset] + newtext + plaintext[offset + len(newtext):]
    return CTR_cryptor(new_plaintext, key, NONCE)


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_25.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_25.py [-h | --help]')
            print('Challenge 25: Break "random access read/write" AES CTR')
            sys.exit()

    # Prepare ciphertext to break
    plaintext = b""
    for line in open('input_25.txt', 'r'):
        plaintext += line.replace("\n", "").encode()
    plaintext = base64.b64decode(plaintext)
    ciphertext = CTR_cryptor(plaintext, CTR_KEY, NONCE)

    # Breaking this cipher with edit function
    altered_ciphertext = edit(ciphertext, CTR_KEY, 0, bytes([0] * len(ciphertext)))
    ''' By substitute ciphertext into all zero bytes, the reault is the key to xor with each byte of plaintext.
    Therefore, xor it with ciphertext recover the plaintext'''
    recovered_plaintext = bytestrxor(ciphertext, altered_ciphertext)
    print("Plaintext recovered? " + str(recovered_plaintext == plaintext))


if __name__ == "__main__":
    main(sys.argv[1:])