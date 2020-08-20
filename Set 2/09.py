import sys
import getopt
import binascii


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('09.py <text_input> <desired_length>')
        sys.exit(2)

    if len(args) != 2:
        print('Invalid number of arguements')
        print('09.py <text_input> <desired_length>')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('09.py <text_input> <desired_length>')
            sys.exit()

    try:
        original_text = args[0].encode()
    except binascii.Error as e:
        print("Decoding Error: " + str(e))
        sys.exit(2)
    else:
        desired_length = int(args[1])
        pad_length = desired_length - len(original_text)
        padded_text = original_text + bytes([pad_length] * pad_length)
        print(pad_length, desired_length, len(original_text))
        print(b"Padded result is " + padded_text)


if __name__ == "__main__":
    main(sys.argv[1:])