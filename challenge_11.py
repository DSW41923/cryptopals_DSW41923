import sys
import getopt
import binascii
import base64
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from challenge_02 import bytestrxor
from challenge_08 import split_by_length
from challenge_09 import padding_to_length
from challenge_10 import CBC_Encryptor


def encryption_oracle(string):
    prefix_length = secrets.choice(range(5, 11))
    affix_length = secrets.choice(range(5, 11))
    plaintext = secrets.token_bytes(prefix_length) + string + secrets.token_bytes(affix_length)
    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    choice = secrets.randbelow(2)
    if choice == 0:
        mode = "ECB"
        plaintext_blocks = split_by_length(plaintext, 16)
        if len(plaintext_blocks[-1]) < 16:
            plaintext_blocks[-1] = padding_to_length(plaintext_blocks[-1], 16)
        plaintext = b''.join(plaintext_blocks)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    elif choice == 1:
        mode = "CBC"
        ciphertext = CBC_Encryptor(key, plaintext, iv)

    return mode, ciphertext

def detect_mode_of_operation(ciphertext):
    ciphertext_block = split_by_length(ciphertext, 16)
    for block in ciphertext_block:
        if (ciphertext_block.count(block) > 1):
            return "ECB"

    choice = secrets.randbelow(2)
    if choice == 0:
        return "ECB"
    elif choice == 1:
        return "CBC"


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('11.py')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('11.py')
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
    print("Detection suceess rate = " + str(success_detection / float(trial_num)) )


if __name__ == "__main__":
    main(sys.argv[1:])