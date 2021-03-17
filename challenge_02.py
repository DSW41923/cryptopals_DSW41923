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
        print('Usage: python3 challenge_02.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_02.py [-h | --help]')
            print('Challenge 02: Fixed XOR')
            sys.exit()

    try:
        origin_text_1 = codecs.decode("1c0111001f010100061a024b53535009181c", 'hex')
        origin_text_2 = codecs.decode("686974207468652062756c6c277320657965", 'hex')
        expected_text = "746865206b696420646f6e277420706c6179"
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
        print("Is the result as expected? " + str(xor_result == expected_text))


if __name__ == "__main__":
    main(sys.argv[1:])
