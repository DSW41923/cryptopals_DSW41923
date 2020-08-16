import sys
import codecs
import getopt
import binascii
import string

from common_utils import bytestrxor


def generate_key(text, desired_length):
    text_multiple = int(desired_length / len(text) + 1)
    key_string = text * text_multiple
    return key_string[:desired_length]


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('05.py <plaintext_input> <key_input> <expected_ciphertext>')
        sys.exit(2)

    if len(args) > 3:
        print('Too many arguements')
        sys.exit(2)
    elif len(args) < 3:
        print('Too few arguements')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('05.py <plaintext_input> <key_input> <expected_ciphertext>')
            sys.exit()

    try:
        origin_plaintext = args[0].encode()
        key_text = args[1].encode()
        expected_ciphertext = args[2]
    except binascii.Error as e:
        print("Decoding Error: " + str(e))
        sys.exit(2)
    else:
        key = generate_key(key_text, len(origin_plaintext))
        original_ciphertext = bytestrxor(origin_plaintext, key)
        ciphertext = codecs.encode(original_ciphertext, encoding='hex').decode()
        print("Encrypted result is: " + ciphertext)
        print("Is encrypted result identical to the expected? " + str(ciphertext == expected_ciphertext))
        import pdb; pdb.set_trace()

if __name__ == "__main__":
    main(sys.argv[1:])