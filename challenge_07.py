import sys
import codecs
import getopt
import binascii
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_07.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_07.py [-h | --help]')
            print('Challenge 07: AES in ECB mode')
            sys.exit()

    try:
        original_ciphertext = ''
        for line in open('input_07.txt', 'r'):
            original_ciphertext += line
    except FileNotFoundError as e:
        print(repr(e))
        sys.exit(2)
    else:

        try:
            ciphertext = base64.b64decode(original_ciphertext.encode())
            key = b"YELLOW SUBMARINE"
        except binascii.Error as e:
            print("Decoding Error: " + str(e))
            sys.exit(2)
        else:
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            print("Decrypted result is: \n" + plaintext.decode())

if __name__ == "__main__":
    main(sys.argv[1:])