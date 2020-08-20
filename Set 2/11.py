import sys
import getopt
import binascii
import base64
import secrets

from common_utils import padding_to_length, split_by_length, bytestrxor, CBC_Encryptor
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def ECB_ecrypt(block_length):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

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

def mode_detector(ciphertext):
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
        opts, args = getopt.getopt(argv,"h:",["help", "oracle"])
    except getopt.GetoptError:
        print('11.py --oracle <plaintext>')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('11.py --oracle <plaintext>')
            sys.exit()
        if opt == "--oracle":
            try:
                plaintext = args[0].encode()
            except binascii.Error as e:
                print("Decoding Error: " + str(e))
                sys.exit(2)
            except IndexError as e:
                print('11.py -m <plaintext>')
                sys.exit(2)
            else:
                mode, ciphertext = encryption_oracle(plaintext)
                print(ciphertext)
                sys.exit()

    trial_num = 100
    success_detection = 0
    for x in range(trial_num):
        testing_length = 128
        testing_inputs = secrets.token_bytes(1) * testing_length
        mode, ciphertext = encryption_oracle(testing_inputs)
        detected_mode = mode_detector(ciphertext)
        if detected_mode == mode:
            # print("Correct Detection!")
            success_detection += 1
        # else:
            # print("Wrong Detection!")
    print("Detection suceess rate = " + str(success_detection / float(trial_num)) )


if __name__ == "__main__":
    main(sys.argv[1:])