import sys
import codecs
import getopt
import binascii


def bytestrxor(a, b):
    return bytes([x ^ y for (x, y) in zip(a, b)])


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('1-2.py <first_hex_string_input> <second_hex_string_input> <expected_base64_output>')
        sys.exit(2)
    if len(args) > 3:
        print('Too many arguements')
        sys.exit(2)
    elif len(args) < 3:
        print('Too few arguements')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('1-2.py <first_hex_string_input> <second_hex_string_input> <expected_base64_output>')
            sys.exit()

    try:
        origin_text_1 = codecs.decode(args[0], 'hex')
        origin_text_2 = codecs.decode(args[1], 'hex')
        expected_text = args[2]
    except binascii.Error as e:
        print("Decoding Error: " + str(e))
        sys.exit(2)
    else:
        
        if len(origin_text_1) != len(origin_text_2):
            print('Both inputs must have same length.')
            sys.exit(2)
        
        xor_result_str = bytestrxor(origin_text_1, origin_text_2)
        xor_result = codecs.encode(xor_result_str, encoding='hex').decode()
        print("Xored result is: " + xor_result)
        print("Is converted result identical to the expected? " + str(xor_result == expected_text))

if __name__ == "__main__":
    main(sys.argv[1:])