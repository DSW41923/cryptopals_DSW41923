import sys
import codecs
import getopt
import binascii


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('01.py <hex_string_input> <expected_base64_output>')
        sys.exit(2)
    if len(args) > 2:
        print('too many arguements')
        sys.exit(2)
    elif len(args) < 2:
        print('too few arguements')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('01.py <hex_string_input> <expected_base64_output>')
            sys.exit()

    origin_text = args[0]
    expected_text = args[1]
    try:
        convert_result = codecs.encode(codecs.decode(origin_text, 'hex'), encoding='base64').decode().replace("\n", "")
    except binascii.Error as e:
        print("Decoding Error: " + str(e))
        sys.exit(2)
    else:
        print("Converted result is: " + convert_result)
        print("Is converted result identical to the expected? " + str(convert_result == expected_text))

if __name__ == "__main__":
    main(sys.argv[1:])