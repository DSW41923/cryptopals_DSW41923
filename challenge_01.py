import sys
import codecs
import getopt
import binascii


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_01.py')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_01.py')
            print('Challenge 01: Convert hex to base64')
            sys.exit()

    origin_text = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    expected_text = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    try:
        convert_result = codecs.encode(codecs.decode(origin_text, 'hex'), encoding='base64').decode().replace("\n", "")
    except binascii.Error as e:
        print("Decoding Error: " + str(e))
        sys.exit(2)
    else:
        print("Converted result is: " + convert_result)
        print("Is converted result as expected? " + str(convert_result == expected_text))

if __name__ == "__main__":
    main(sys.argv[1:])