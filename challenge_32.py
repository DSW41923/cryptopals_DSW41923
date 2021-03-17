import sys
import getopt
import secrets

from challenge_31 import get_correct_signature


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_32.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_32.py [-h | --help]')
            print('Challenge 32: Break HMAC-SHA1 with a slightly less artificial timing leak')
            sys.exit()

    target_url = 'http://127.0.0.1:8000/challenges/32'
    file_name = secrets.token_bytes(16).hex()
    timing_difference = 0.005
    correct_signature = get_correct_signature(target_url, file_name, timing_difference)

    if correct_signature:
        print("Correct signature of file {} is {}".format(file_name, correct_signature.hex()))
    else:
        print("Unexpected error occurred while cracking signature of file " + file_name)


if __name__ == "__main__":
    main(sys.argv[1:])