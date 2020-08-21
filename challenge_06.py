import sys
import codecs
import getopt
import binascii
import base64

from challenge_02 import bytestrxor
from challenge_03 import evaluate_palintext


def hamming_distance(string_1, string_2):
    if type(string_1) == bytes:
        byte_str_1 = string_1
    else:
        byte_str_1 = string_1.encode()

    if type(string_2) == bytes:
        byte_str_2 = string_2
    else:
        byte_str_2 = string_2.encode()

    xor_result = bytestrxor(byte_str_1, byte_str_2)
    h_distance = 0
    for byte in xor_result:
        h_distance += bin(byte).count('1')
    return h_distance


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_06.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_06.py [-h | --help]')
            print('Challenge 06: Break repeating-key XOR')
            sys.exit()

    try:
        original_ciphertext = ''
        for line in open('input_06.txt', 'r'):
            original_ciphertext += line
    except FileNotFoundError as e:
        print(repr(e))
        sys.exit(2)
    else:

        try:
            ciphertext = base64.b64decode(original_ciphertext.encode())
        except binascii.Error as e:
            print("Decoding Error: " + str(e))
            sys.exit(2)
        else:
            # Testing Hamming distance function
            print(hamming_distance("this is a test", "wokka wokka!!!"))

            # defining key size
            trial_blocks = 4
            avg_distance_per_length = []
            for trial_length in range(1, len(ciphertext) // trial_blocks):
                distance = 0
                trial_start = 0
                trial_times = 1

                while trial_times < trial_blocks:
                    first_block = ciphertext[trial_start:trial_start + trial_length]
                    second_block = ciphertext[trial_start + trial_length:trial_start + 2 * trial_length]
                    distance += hamming_distance(first_block, second_block)
                    trial_times += 1
                    trial_start = trial_start + trial_length

                avg_distance = (distance / trial_times) / trial_length
                avg_distance_per_length.append(avg_distance)

            min_avg_distance = min(avg_distance_per_length)
            sorted_distance = avg_distance_per_length.copy()
            sorted_distance.sort()
            possible_plaintexts = []
            for i in sorted_distance[:5]:
                key_length = avg_distance_per_length.index(i) + 1
                best_evaluations = []

                for j in range(key_length):
                    partial_ciphertext_bytes = []

                    for k in range(j, len(ciphertext), key_length):
                        partial_ciphertext_bytes.append(ciphertext[k])
                    
                    partial_ciphertext = bytes(partial_ciphertext_bytes)

                    best_scoring = 0
                    best_evaluation = ('', '')
                    for x in range(1, 256):
                        possible_key = x.to_bytes(1, 'big') * len(partial_ciphertext)
                        possible_plaintext = bytestrxor(partial_ciphertext, possible_key)
                        current_scoring = evaluate_palintext(possible_plaintext)
                        if current_scoring > best_scoring:
                            best_scoring = current_scoring
                            best_evaluation = (possible_key, possible_plaintext)
                    if best_evaluation[0] != '':
                        best_evaluations.append(best_evaluation)

                if len(best_evaluations) == key_length:
                    possible_key_bytes = bytes([b[0][0] for b in best_evaluations])
                    displaced_plaintext = [p[1] for p in best_evaluations]
                    plaintext_bytes = [0] * len(ciphertext)
                    for x, pt in enumerate(displaced_plaintext):
                        for y, char in enumerate(pt):
                            plaintext_bytes[y * key_length + x] = char
                    possible_plaintexts.append({'key': possible_key_bytes, "plaintext": bytes(plaintext_bytes)})

            best_pt_scoring = 0
            best_pt = {}
            for possible_pt in possible_plaintexts:
                current_scoring = evaluate_palintext(possible_pt['plaintext'])
                if current_scoring > best_pt_scoring:
                    best_pt_scoring = current_scoring
                    best_pt = possible_pt
            print("Decrypted result is: \n" + possible_pt['plaintext'].decode())
            print("Key (in hex) is: " + codecs.encode(possible_pt['key'], encoding='hex').decode())

if __name__ == "__main__":
    main(sys.argv[1:])