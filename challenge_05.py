import sys
import codecs
import getopt
import binascii
import string

from challenge_02 import bytestrxor


def extend_key(text, desired_length):
    text_multiple = int(desired_length / len(text) + 1)
    key_string = text * text_multiple
    return key_string[:desired_length]


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_05.py')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_05.py')
            print('Challenge 05: Implement repeating-key XOR')
            sys.exit()

    try:
        origin_plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        key_text = b"ICE"
        expected_ciphertext = ("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
            "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    except binascii.Error as e:
        print("Decoding Error: " + str(e))
        sys.exit(2)
    else:
        key = extend_key(key_text, len(origin_plaintext))
        original_ciphertext = bytestrxor(origin_plaintext, key)
        ciphertext = codecs.encode(original_ciphertext, encoding='hex').decode()
        print("Encrypted result is: " + ciphertext)
        print("Is the result as expected? " + str(ciphertext == expected_ciphertext))

if __name__ == "__main__":
    main(sys.argv[1:])