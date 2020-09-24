import sys
import codecs
import getopt
import binascii


def split_by_length(text, length):

    return [text[i:i + length] for i in range(0, len(text), length)]


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_08.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_08.py [-h | --help]')
            print('Challenge 08: Detect AES in ECB mode')
            sys.exit()

    try:
        ecb_lines = []
        for line_num, line in enumerate(open('input_08.txt', 'r')):
            try:
                line = line.replace("\n", "")
                ciphertext = codecs.decode(line, 'hex')
            except binascii.Error as e:
                print("Decoding Error: " + str(e))
                sys.exit(2)
            else:
                ciphertext_block = split_by_length(ciphertext, 16)
                for block in ciphertext_block:
                    if (ciphertext_block.count(block) > 1) and (line_num not in ecb_lines):
                        ecb_lines.append(line_num)
                        
        for line_num in ecb_lines:
            print(str(line_num) + " is AES in ECB mode!!")
    except FileNotFoundError as e:
        print(repr(e))
        sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])