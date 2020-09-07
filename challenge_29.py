import sys
import codecs
import getopt
import binascii
import secrets
import struct

from challenge_08 import split_by_length
from challenge_28 import SHA1_prefix_MAC


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_29.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_29.py [-h | --help]')
            print('Challenge 29: Break a SHA-1 keyed MAC using length extension')
            sys.exit()

    key = secrets.token_bytes(16)
    text = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    target = b';admin=true'

    MAC_generator = SHA1_prefix_MAC(key)
    original_MAC = MAC_generator.MAC_text(text)
    new_states = tuple(map(lambda x: int(x, 16), split_by_length(original_MAC.hex(), 8)))

    for x in range(2 ** 64 - len(text)):

        # Getting original padding
        trial_text = b'A' * x + text
        original_padded_text_bin = MAC_generator.preprocess(trial_text)
        original_padded_text = int(original_padded_text_bin, 2).to_bytes(len(original_padded_text_bin) // 8, byteorder='big')
        trial_mali_text = original_padded_text + target

        # Caculating hash from new blocks with states provided
        MAC_generator.set_chunk(*new_states)
        padded_trial_mali_text_bin = MAC_generator.preprocess(trial_mali_text)
        mali_MAC = MAC_generator.calculate_hashing(padded_trial_mali_text_bin[1024:])
        if MAC_generator.verify(trial_mali_text[x:], mali_MAC):
            print("Got It!")
            print(b"Desired extended text is: " + trial_mali_text[x:])
            break

if __name__ == "__main__":
    main(sys.argv[1:])