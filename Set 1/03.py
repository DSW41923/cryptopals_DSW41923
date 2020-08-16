import sys
import codecs
import getopt
import binascii
import string

from common_utils import bytestrxor


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

    return point

def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('03.py <ciphertext_input>')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguements')
        sys.exit(2)
    elif len(args) < 1:
        print('Too few arguements')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('03.py <ciphertext_input>')
            sys.exit()

    try:
        origin_ciphertext = codecs.decode(args[0], 'hex')
    except binascii.Error as e:
        print("Decoding Error: " + str(e))
        sys.exit(2)
    else:
        best_evaluation_point = 0
        best_evaluation_plaintext = []
        for x in range(1, 256):
            possible_key = x.to_bytes(1, 'big') * len(origin_ciphertext)
            possible_plaintext = bytestrxor(origin_ciphertext, possible_key)
            current_evaluation_point = evaluate_palintext(possible_plaintext)
            if current_evaluation_point > best_evaluation_point:
                best_evaluation_point = current_evaluation_point
                best_evaluation_plaintext = [(possible_key, possible_plaintext)]
            elif current_evaluation_point == best_evaluation_point:
                best_evaluation_plaintext.append((possible_key, possible_plaintext))
            
        for key, plaintext in best_evaluation_plaintext:
            print("Possible plaintext could be: " + plaintext.decode())
            print("Possible key (in hex) could be: " + codecs.encode(key, 'hex').decode())

if __name__ == "__main__":
    main(sys.argv[1:])