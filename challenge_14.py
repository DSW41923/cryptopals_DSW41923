import sys
import getopt
import base64
import secrets

from challenge_08 import split_by_length
from challenge_11 import ecb_encryptor
from challenge_12 import detect_mode_of_operation, detect_block_length



KEY = secrets.token_bytes(16)


def prefix_ecb_encryption_oracle(plaintext):

    prefix_length = secrets.choice(range(5, 11))
    prefix = secrets.token_bytes(prefix_length)
    plaintext = prefix + plaintext
    ciphertext = ecb_encryptor(plaintext, KEY)

    return ciphertext


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_14.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_14.py [-h | --help]')
            print('Challenge 14: Byte-at-a-time ECB decryption (Harder)')
            sys.exit()

    # noinspection SpellCheckingInspection
    target = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
            "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
            "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
            "YnkK")
    target_bytes = base64.b64decode(target.encode())

    # Detecting length of block and mode of operation
    block_length = detect_block_length(prefix_ecb_encryption_oracle)
    testing_inputs = secrets.token_bytes(1) * 128
    ciphertext = prefix_ecb_encryption_oracle(testing_inputs)
    mode_of_operation = detect_mode_of_operation(ciphertext)

    # Generate dictionary for all possible ciphertext
    dictionary = {}
    for x in range(256):
        for y in range(50):
            dictionary_pt = b'A' * block_length + bytes([x])
            dictionary_ct = prefix_ecb_encryption_oracle(dictionary_pt)
            dictionary_ct_blocks = split_by_length(dictionary_ct, block_length)
            dictionary.setdefault(dictionary_ct_blocks[-1], x)

    result = []
    if mode_of_operation == "ECB":
        for byte in target_bytes:
            trial_plaintext = b'A' * block_length + bytes([byte])
            trial_ciphertext = prefix_ecb_encryption_oracle(trial_plaintext)
            trial_ciphertext_blocks = split_by_length(trial_ciphertext, block_length)
            result.append(dictionary.get(trial_ciphertext_blocks[-1], 0))

    target_result = bytes(result).decode()
    print("Target is :\n" + target_result)
    print("Is result correct? " + str(target_result == target_bytes.decode()))


if __name__ == "__main__":
    main(sys.argv[1:])