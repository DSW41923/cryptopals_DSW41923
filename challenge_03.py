import sys
import codecs
import getopt
import binascii

from challenge_02 import bytestrxor


CHAR_FREQ = {'a': 0.0651738, 'b': 0.0124248, 'c': 0.0217339, 'd': 0.0349835, 'e': 0.1041442, 'f': 0.0197881,
'g': 0.0158610, 'h': 0.0492888, 'i': 0.0558094, 'j': 0.0009033, 'k': 0.0050529, 'l': 0.0331490, 'm': 0.0202124,
'n': 0.0564513, 'o': 0.0596302, 'p': 0.0137645, 'q': 0.0008606, 'r': 0.0497563, 's': 0.0515760, 't': 0.0729357,
'u': 0.0225134, 'v': 0.0082903, 'w': 0.0171272, 'x': 0.0013692, 'y': 0.0145984, 'z': 0.0007836, ' ': 0.1918182}

def evaluate_palintext(plaintext):
    point = 0
    for byte in plaintext:
        if byte >= 128:
            return -1

        char = byte.to_bytes(1, 'big').decode()

        # Improved with frequency
        point += CHAR_FREQ.get(char.lower(), 0)

    return point


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_03.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_03.py [-h | --help]')
            print('Challenge 03: Single-byte XOR cipher')
            sys.exit()

    try:
        origin_ciphertext = codecs.decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", 'hex')
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