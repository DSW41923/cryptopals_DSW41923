import sys
import getopt
import binascii
import string

from challenge_09 import padding_to_length


def verify_padding(text, length):
    if type(text) != bytes:
        text = text.encode()
    
    if len(text) == length:
        padding_byte = text[-1]
        padding_byte_count = 1
        for x in range(2, padding_byte + 1):
                if text[-x] == padding_byte:
                    padding_byte_count += 1
                else:
                    break
        if padding_byte_count == padding_byte:
            return text[:-padding_byte_count]

    raise ValueError("Invalid Padding!")


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_15.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_15.py [-h | --help]')
            print('Challenge 15: PKCS#7 padding validation')
            sys.exit()

    desired_length = 16
    padded_text = b"ICE ICE BABY\x04\x04\x04\x04"
    print(b"Unpadded result is " + verify_padding(padded_text, desired_length))
    try:
        wrong_padding_text_1 = b"ICE ICE BABY\x05\x05\x05\x05"
        print(b"Unpadded result is " + verify_padding(wrong_padding_text_1, desired_length))
    except ValueError as e:
        print(repr(e))
    try:
        wrong_padding_text_2 = b"ICE ICE BABY\x01\x02\x03\x04"
        print(b"Unpadded result is " + verify_padding(wrong_padding_text_2, desired_length))
    except ValueError as e:
        print(repr(e))


if __name__ == "__main__":
    main(sys.argv[1:])