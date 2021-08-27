import sys
import getopt
import base64
import secrets

from challenge_08 import split_by_length
from challenge_11 import ecb_encryptor

KEY = secrets.token_bytes(16)


def ecb_encryption_oracle(plaintext):
    # Remove random prefix and affix based on challenge 14
    ciphertext = ecb_encryptor(plaintext, KEY)
    return ciphertext


def detect_mode_of_operation(ciphertext):
    ciphertext_block = split_by_length(ciphertext, 16)
    for block in ciphertext_block:
        if ciphertext_block.count(block) > 1:
            return "ECB"
    return "Unknown"


def detect_block_length(oracle):
    previous_ct_length = 0
    for length in range(1, 50):
        plaintext = b'A' * length
        ciphertext = oracle(plaintext)
        if len(ciphertext) != previous_ct_length:
            if previous_ct_length == 0:
                previous_ct_length = len(ciphertext)
            else:
                return len(ciphertext) - previous_ct_length
    return previous_ct_length


# noinspection SpellCheckingInspection
def main(argv):
    try:
        opts, args = getopt.getopt(argv, "h:", ["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_12.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_12.py [-h | --help]')
            print('Challenge 12: Byte-at-a-time ECB decryption (Simple)')
            sys.exit()

    target = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
              "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
              "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
              "YnkK")
    target_bytes = base64.b64decode(target.encode())

    # Detecting length of block and mode of operation
    block_length = detect_block_length(ecb_encryption_oracle)
    testing_inputs = secrets.token_bytes(1) * 128
    ciphertext = ecb_encryption_oracle(testing_inputs)
    mode_of_operation = detect_mode_of_operation(ciphertext)

    # Generate dictionary for all possible ciphertext
    dictionary = {}
    for x in range(256):
        dictionary_pt = b'A' * (block_length - 1) + bytes([x])
        dictionary_ct = ecb_encryption_oracle(dictionary_pt)
        dictionary[dictionary_ct] = x

    result = []
    if mode_of_operation == "ECB":
        for byte in target_bytes:
            trial_plaintext = b'A' * (block_length - 1) + bytes([byte])
            trial_ciphertext = ecb_encryption_oracle(trial_plaintext)
            result.append(dictionary[trial_ciphertext])

    target_result = bytes(result).decode()
    print("Target is :\n" + target_result)
    print("Is result correct? " + str(target_result == target_bytes.decode()))


if __name__ == "__main__":
    main(sys.argv[1:])
