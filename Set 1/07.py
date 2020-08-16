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
        print('1-7.py <ciphertext_fileinput> <key>')
        sys.exit(2)

    if len(args) != 2:
        print('Invalid number of arguements')
        print('1-7.py <ciphertext_fileinput> <key>')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('1-7.py <ciphertext_fileinput> <key>')
            sys.exit()

    try:
        original_ciphertext = ''
        for line in open(args[0], 'r'):
            original_ciphertext += line
    except FileNotFoundError as e:
        print(repr(e))
        sys.exit(2)
    else:

        try:
            ciphertext = base64.b64decode(original_ciphertext.encode())
            # Key = "YELLOW SUBMARIN"
            key = args[1].encode()
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