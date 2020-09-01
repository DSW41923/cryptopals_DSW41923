import sys
import getopt
import binascii
import base64
import secrets

from challenge_02 import bytestrxor
from challenge_03 import evaluate_palintext
from challenge_19 import fixed_nonce_CTR_crtyptor


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_20.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_20.py [-h | --help]')
            print('Challenge 20: Break fixed-nonce CTR statistically')
            sys.exit()

    plaintexts = []
    ciphertexts = []
    for line in open('input_20.txt', 'r'):
        plaintext = base64.b64decode(line.encode())
        plaintexts.append(plaintext)
        ciphertexts.append(fixed_nonce_CTR_crtyptor(plaintext))

    # Consider bytes at same position in different ciphertext as result of single-char XOR
    separated_ciphertext_by_bytes = [b''] * max([len(c) for c in ciphertexts])
    for ciphertext in ciphertexts:
        for byte_num, byte in enumerate(ciphertext):
            separated_ciphertext_by_bytes[byte_num] += byte.to_bytes(1, 'big')

    key_byte_candidates = []
    for byted_ct in separated_ciphertext_by_bytes:
        if len(byted_ct) < len(ciphertexts):
            continue
        best_score = 0
        key_candidate = b''
        for y in range(256):
            trial_byte = y.to_bytes(1, 'big')
            possible_key_bytes = trial_byte * len(byted_ct)
            possible_pt = bytestrxor(byted_ct, possible_key_bytes)
            trial_score = evaluate_palintext(possible_pt)
            if trial_score >= best_score:
                best_score = trial_score
                key_candidate += trial_byte
        key_byte_candidates.append(key_candidate)

    # Reducing candidates by choosing the last candidate for each byte as beginning
    temporary_key = b''
    for byte in key_byte_candidates:
        key_byte = byte[-1].to_bytes(1, 'big')
        temporary_key += key_byte

    # Keep the fixing part here to fix some byte if desired
    while True:
        current_plaintexts = b"\n".join([bytestrxor(temporary_key, c) for c in ciphertexts])
        print("Current decrypt result is: ")
        print(current_plaintexts.decode())
        to_fix = input("Input byte number to fix key or N/n to end fixing: ")
        if to_fix in ["N", "n"]:
            break
        else:
            try:
                byte_num_to_fix = int(to_fix)
                print("Candidates of key bytes for byte " + to_fix + " is:")
                byte_candidates = list(map(int, key_byte_candidates[byte_num_to_fix]))
                print(byte_candidates)
                print("Current key bytes for byte " + to_fix + " is: " + str(temporary_key[byte_num_to_fix]))
                byte_selection = int(input("Enter a new byte: ")).to_bytes(1, 'big')
                temporary_key = temporary_key[:byte_num_to_fix] + byte_selection + temporary_key[byte_num_to_fix + 1:]
            except TypeError:
                continue

    final_plaintexts = b"\n".join([bytestrxor(temporary_key, c) for c in ciphertexts])
    print("Final decrypt result is: ")
    print(final_plaintexts.decode())


if __name__ == "__main__":
    main(sys.argv[1:])