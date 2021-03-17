import sys
import getopt
import base64
import secrets

from challenge_02 import bytestrxor
from challenge_03 import evaluate_plaintext
from challenge_18 import ctr_cryptor


AES_KEY = secrets.token_bytes(16)

def fixed_nonce_ctr_cryptor(text):
    nonce = bytes([0] * 8)
    return ctr_cryptor(text, AES_KEY, nonce)

def get_key_byte_candidates(ciphertexts):
    # Consider bytes at same position in different ciphertext as result of single-char XOR
    ciphertext_bytes = [b''] * max([len(c) for c in ciphertexts])
    for ciphertext in ciphertexts:
        for byte_num, byte in enumerate(ciphertext):
            ciphertext_bytes[byte_num] += byte.to_bytes(1, 'big')

    key_byte_candidates = []
    for byte in ciphertext_bytes:
        best_score = 0
        key_candidate = b''
        for y in range(256):
            trial_byte = y.to_bytes(1, 'big')
            possible_key_bytes = trial_byte * len(byte)
            possible_pt = bytestrxor(byte, possible_key_bytes)
            trial_score = evaluate_plaintext(possible_pt)
            if trial_score >= best_score:
                best_score = trial_score
                key_candidate += trial_byte
        key_byte_candidates.append(key_candidate)
    return key_byte_candidates

def fix_key(key, ciphertexts, key_byte_candidates):
    while True:
        current_plaintexts = b"\n".join([bytestrxor(key, c) for c in ciphertexts])
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
                print("Current key bytes for byte " + to_fix + " is: " + str(key[byte_num_to_fix]))
                byte_selection = int(input("Enter a new byte: ")).to_bytes(1, 'big')
                key = key[:byte_num_to_fix] + byte_selection + key[byte_num_to_fix + 1:]
            except TypeError:
                continue

    return key


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_19.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_19.py [-h | --help]')
            print('Challenge 19: Break fixed-nonce CTR mode using substitutions')
            sys.exit()

    plaintexts = []
    ciphertexts = []
    for line in open('input_19.txt', 'r'):
        plaintext = base64.b64decode(line.encode())
        plaintexts.append(plaintext)
        ciphertexts.append(fixed_nonce_ctr_cryptor(plaintext))

    key_byte_candidates = get_key_byte_candidates(ciphertexts)

    # Reducing candidates
    temporary_key = b''
    for byte in key_byte_candidates:
        key_byte = secrets.choice(byte).to_bytes(1, 'big')
        temporary_key += key_byte

    final_key = fix_key(temporary_key, ciphertexts, key_byte_candidates)

    final_plaintexts = b"\n".join([bytestrxor(final_key, c) for c in ciphertexts])
    print("Final decrypt result is: ")
    print(final_plaintexts.decode())


if __name__ == "__main__":
    main(sys.argv[1:])
