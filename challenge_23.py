import sys
import getopt
import binascii
import base64
import secrets
import time

from challenge_21 import MT19937_RNG


def recover_rng_state(source):
    state = []
    for y in source:
        x_n = int(y, 2)

        # Inverse last computation
        # x_n = x_3 ^ (x_3 >> 18)
        x_3 = x_n ^ (x_n >> 18)

        # Inverse second last computation
        # x_3 = x_2 ^ ((x_2 << 15) & 0xEFC60000)
        x_2 = x_3 % (2 ** 17)
        x_2 += ((((x_2 >> 2) & (0xEFC6 >> 1)) ^ (x_3 >> 17))) << 17

        # Inverse second computation
        # x_2 = x_1 ^ ((x_1 << 7) & 0x9D2C5680)
        x_1 = x_2 % (2 ** 7)
        magic_num = 0x9D2C5680
        for i in range(3):
            a = 7 * i
            b = 7 * (i + 1)
            c = 2 ** 7
            l = (x_1 >> a) % c
            m = (magic_num >> b) % c
            n = (x_2 >> b) % c
            x_1 += ((l & m) ^ n) << b
        x_1 += ((((x_1 >> 21) % 16) & ((magic_num >> 28) % 16)) ^ ((x_2 >> 28)) % 16) << 28

        # Inverse first computation
        # x_1 = x_0 ^ ((x_0 >> 11) & 0xFFFFFFFF)
        x_0 = (x_1 >> 21) << 21
        x_0 += (((x_1 >> 10) % (2 ** 11)) ^ ((x_0 >> 21) & int("1" * 11, 2))) << 10
        x_0 += (x_1 % (2 ** 10)) ^ (((x_0 >> 11) % (2 ** 10)) & int("1" * 10, 2))

        state.append(x_0)

    return state


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_23.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_23.py [-h | --help]')
            print('Challenge 23: Clone an MT19937 RNG from its output')
            sys.exit()

    seed = secrets.choice(range(2 ** 32))
    target_rng = MT19937_RNG(seed)
    results = []
    for x in range(624):
        number = target_rng.extract_number()
        results.append(number)

    rng_states = recover_rng_state(results)
    cloned_rng = MT19937_RNG(0)
    cloned_rng.state = rng_states
    for x in range(624):
        number_target = target_rng.extract_number()
        number_cloned = cloned_rng.extract_number()
        if number_target != number_cloned:
            print("Incorrect cloning!")
            sys.exit(2)
    print("Correct cloning! Good Job!")


if __name__ == "__main__":
    main(sys.argv[1:])