import sys
import getopt
import base64

from challenge_02 import bytestrxor
from challenge_03 import evaluate_plaintext
from challenge_19 import fixed_nonce_ctr_cryptor, fix_key


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "h:", ["help"])
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
        ciphertexts.append(fixed_nonce_ctr_cryptor(plaintext))

    # Consider bytes at same position in different ciphertext as result of single-char XOR
    ciphertext_bytes = [b''] * max([len(c) for c in ciphertexts])
    for ciphertext in ciphertexts:
        for byte_num, byte in enumerate(ciphertext):
            ciphertext_bytes[byte_num] += byte.to_bytes(1, 'big')

    key_byte_candidates = []
    for ct_bytes in ciphertext_bytes:
        if len(ct_bytes) < len(ciphertexts):
            continue
        best_score = 0
        key_candidate = b''
        for y in range(256):
            trial_byte = y.to_bytes(1, 'big')
            possible_key_bytes = trial_byte * len(ct_bytes)
            possible_pt = bytestrxor(ct_bytes, possible_key_bytes)
            trial_score = evaluate_plaintext(possible_pt)
            if trial_score >= best_score:
                best_score = trial_score
                key_candidate += trial_byte
        key_byte_candidates.append(key_candidate)

    # Reducing candidates by choosing the last candidate for each byte as beginning
    temporary_key = b''
    for byte in key_byte_candidates:
        key_byte = byte[-1].to_bytes(1, 'big')
        temporary_key += key_byte

    final_key = fix_key(temporary_key, ciphertexts, key_byte_candidates)

    final_plaintexts = b"\n".join([bytestrxor(final_key, c) for c in ciphertexts])
    print("Final decrypt result is: ")
    print(final_plaintexts.decode())


if __name__ == "__main__":
    main(sys.argv[1:])
