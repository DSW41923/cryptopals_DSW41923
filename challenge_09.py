import sys
import getopt
import binascii


def padding_to_length(text, length):
    pad_length = length - len(text)
    if type(text) != bytes:
        text = text.encode()
    return text + bytes([pad_length] * pad_length)


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('09.py')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('09.py')
            sys.exit()

    try:
        original_text = b"YELLOW SUBMARINE"
    except binascii.Error as e:
        print("Decoding Error: " + str(e))
        sys.exit(2)
    else:
        desired_length = 20
        padded_text = padding_to_length(original_text, desired_length)
        print(b"Padded result is " + padded_text)


if __name__ == "__main__":
    main(sys.argv[1:])