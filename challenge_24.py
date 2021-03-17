import sys
import getopt
import secrets
import time

from challenge_02 import bytestrxor
from challenge_21 import MT19937RNG


def mt19937_rng_cryptor(text, seed):

    rng = MT19937RNG(seed)
    key_string = rng.extract_number()

    while len(key_string) < (len(text) * 8):
        key_string += rng.extract_number()

    key_byte = int(key_string, 2).to_bytes((len(key_string) + 7) // 8, byteorder='little')

    return bytestrxor(text, key_byte[:len(text)])

def random_prefix_text(text):
    prefix_byte_length = secrets.choice(range(64))
    text = secrets.token_bytes(prefix_byte_length) + text
    return text


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_24.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_24.py [-h | --help]')
            print('Challenge 24: Create the MT19937 stream cipher and break it')
            sys.exit()

    # Testing encrypt and decrypt
    plaintext = random_prefix_text(b"AAAAAAAAAAAAAAAAAAAA")
    testing_seed = secrets.choice(range(2 ** 16))
    ciphertext = mt19937_rng_cryptor(plaintext, testing_seed)
    if mt19937_rng_cryptor(ciphertext, testing_seed) != plaintext:
        print("Incorrect cipher implementation!")
    else:
        print("Correct Implementation! Good Job!")

    # Manipulate plaintext to recover key(seed) from ciphertext
    plaintext = random_prefix_text(b"A" * 7)
    testing_seed = secrets.choice(range(2 ** 16))
    ciphertext = mt19937_rng_cryptor(plaintext, testing_seed)
    for s in range(2 ** 16):
        trial_plaintext = mt19937_rng_cryptor(ciphertext, s)
        if b"AAAA" in trial_plaintext:
            print("Got seed!")
            print("Seed is " + bin(s)[2:].zfill(16))
            break

    # Generate Key Rest Token with RNG and break it
    seed = int(time.time())
    target_rng = MT19937RNG(seed)
    reset_token = target_rng.extract_number()
    time.sleep(secrets.choice(range(40, 1000)))

    trial_start_time = time.time()
    for s in range(2 ** 16):
        trial_seed = int(trial_start_time) - s
        trial_token = MT19937RNG(trial_seed).extract_number()
        if trial_token == reset_token:
            print("Got seed for generating reset token!")
            print("Seed is " + bin(trial_seed)[2:].zfill(32))
            break


if __name__ == "__main__":
    main(sys.argv[1:])
