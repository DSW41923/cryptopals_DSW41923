import sys
import codecs
import getopt
import binascii

from challenge_02 import bytestrxor
from challenge_03 import evaluate_plaintext


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_04.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_04.py [-h | --help]')
            print('Challenge 04: Detect single-character XOR')
            sys.exit()

    try:
        file_input = open('input_04.txt', 'r')
        ciphertexts = file_input.read().split("\n")
    except FileNotFoundError as e:
        print(repr(e))
        sys.exit(2)
    else:
        per_line_analysis = []
        for ct in ciphertexts:
            try:
                origin_ciphertext = codecs.decode(ct, 'hex')
            except binascii.Error as e:
                print(ct)
                print("Decoding Error: " + str(e))
                sys.exit(2)

            best_evaluation_point = 0
            best_evaluation_plaintext = []
            for x in range(1, 256):
                possible_key = x.to_bytes(1, 'big') * len(origin_ciphertext)
                possible_plaintext = bytestrxor(origin_ciphertext, possible_key)
                current_evaluation_point = evaluate_plaintext(possible_plaintext)
                if current_evaluation_point > best_evaluation_point:
                    best_evaluation_point = current_evaluation_point
                    best_evaluation_plaintext = [(current_evaluation_point, possible_key, possible_plaintext)]
                elif current_evaluation_point == best_evaluation_point:
                    best_evaluation_plaintext.append((current_evaluation_point, possible_key, possible_plaintext))
            for score, key, plaintext in best_evaluation_plaintext:
                per_line_analysis.append((ciphertexts.index(ct), score, key, plaintext))

        best_score = 0
        best_lines = []
        for line_num, score, key, plaintext in per_line_analysis:
            if score > best_score:
                best_score = score
                best_lines = [(line_num, score, key, plaintext)]
            elif score == best_score:
                best_lines.append((line_num, best_score, key, plaintext))

        for line_num, score, key, plaintext in best_lines:
            print("Best line number is " + str(line_num + 1))
            print("Possible plaintext could be: " + plaintext.decode())
            print("Possible key (in hex) could be: " + codecs.encode(key, 'hex').decode())

        file_input.close()


if __name__ == "__main__":
    main(sys.argv[1:])