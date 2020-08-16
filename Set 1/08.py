import sys
import codecs
import getopt
import binascii
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from common_utils import split_by_length


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('08.py <ciphertext_fileinput>')
        sys.exit(2)

    if len(args) != 1:
        print('Invalid number of arguements')
        print('08.py <ciphertext_fileinput>')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('08.py <ciphertext_fileinput>')
            sys.exit()

    try:
        ECB_lines = []
        for line_num, line in enumerate(open(args[0], 'r')):
            try:
                line = line.replace("\n", "")
                ciphertext = codecs.decode(line, 'hex')
            except binascii.Error as e:
                print("Decoding Error: " + str(e))
                sys.exit(2)
            else:
                ciphertext_block = split_by_length(ciphertext, 16)
                for block in ciphertext_block:
                    if (ciphertext_block.count(block) > 1) and (line_num not in ECB_lines):
                        ECB_lines.append(line_num)
                        
        for line_num in ECB_lines:
            print(str(line_num) + " is AES in ECB mode!!")
    except FileNotFoundError as e:
        print(repr(e))
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])