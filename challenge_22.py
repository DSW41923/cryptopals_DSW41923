import sys
import getopt
import binascii
import base64
import secrets
import time

from challenge_21 import MT19937_RNG


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_22.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_22.py [-h | --help]')
            print('Challenge 22: Crack an MT19937 seed')
            sys.exit()

    time.sleep(secrets.choice(range(40, 1000)))
    seed = int(time.time())
    target_rng = MT19937_RNG(seed)
    time.sleep(secrets.choice(range(40, 1000)))
    number = target_rng.extract_number()

    cracking_time = int(time.time())
    for x in range(2000):
        cracking_seed = cracking_time - x
        trial_rng = MT19937_RNG(cracking_seed)
        trial_number = trial_rng.extract_number()
        if trial_number == number:
            print("Cracking Successfully!")
            print("Seed is " + str(cracking_seed))


if __name__ == "__main__":
    main(sys.argv[1:])