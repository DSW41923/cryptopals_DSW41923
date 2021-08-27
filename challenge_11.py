import sys
import getopt
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from challenge_08 import split_by_length
from challenge_09 import padding_to_length
from challenge_10 import cbc_encryptor


def ecb_encryptor(plaintext, key):
    plaintext_blocks = split_by_length(plaintext, 16)
    if len(plaintext_blocks[-1]) < 16:
        plaintext_blocks[-1] = padding_to_length(plaintext_blocks[-1], 16)
    plaintext = b''.join(plaintext_blocks)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    return ciphertext


def encryption_oracle(string):
    prefix_length = secrets.choice(range(5, 11))
    affix_length = secrets.choice(range(5, 11))
    plaintext = secrets.token_bytes(prefix_length) + string + secrets.token_bytes(affix_length)
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    choice = secrets.randbelow(2)
    if choice == 0:
        return "ECB", ecb_encryptor(plaintext, key)
    elif choice == 1:
        return "CBC", cbc_encryptor(key, plaintext, iv)


def detect_mode_of_operation(ciphertext):
    ciphertext_block = split_by_length(ciphertext, 16)
    for block in ciphertext_block:
        if ciphertext_block.count(block) > 1:
            return "ECB"

    choice = secrets.randbelow(2)
    if choice == 0:
        return "ECB"
    elif choice == 1:
        return "CBC"


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "h:", ["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_11.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_11.py [-h | --help]')
            print('Challenge 11: An ECB/CBC detection oracle')
            sys.exit()

    trial_num = 100
    success_detection = 0
    for x in range(trial_num):
        testing_length = 128
        testing_inputs = secrets.token_bytes(1) * testing_length
        mode, ciphertext = encryption_oracle(testing_inputs)
        detected_mode = detect_mode_of_operation(ciphertext)
        if detected_mode == mode:
            success_detection += 1
    print("Detection success rate = " + str(success_detection / float(trial_num)))


if __name__ == "__main__":
    main(sys.argv[1:])
