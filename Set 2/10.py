import sys
import getopt
import binascii
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from common_utils import padding_to_length, split_by_length, bytestrxor


def CBC_Encryptor(key, plaintext, iv):
    # Prepare encryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    # Make Plaintext Blocks
    ciphertext_result = []
    plaintext_blocks = split_by_length(plaintext, 16)
    for block_num, block in enumerate(plaintext_blocks):
        if len(block) < 16:
            block = padding_to_length(block, 16)

        if block_num == 0:
            pt = bytestrxor(block, iv)
        else:
            pt = bytestrxor(block, ciphertext_result[block_num - 1])
        ciphertext = encryptor.update(pt)
        ciphertext_result.append(ciphertext)
    return b''.join(ciphertext_result)


def CBC_Decryptor(key, ciphertext):
    # Prepare decryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    # Make Ciphertext Blocks
    plaintext_result = []
    ciphertext_blocks = split_by_length(ciphertext, 16)
    for block_num, block in enumerate(ciphertext_blocks[1:]):

        plaintext_block = decryptor.update(block)
        pt_block = bytestrxor(plaintext_block, ciphertext_blocks[block_num])
        plaintext_result.append(pt_block)

    return b''.join(plaintext_result)


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:m",["help", "demo"])
    except getopt.GetoptError:
        print('10.py -m <E:encrypt/D:decrypt> <plaintext/ciphertext> <key> <IV>')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('10.py -m <E:encrypt/D:decrypt> <plaintext/ciphertext> <key> <IV>')
            sys.exit()
        if opt == '--demo':
            try:
                original_ciphertext = ''
                for line in open('10.txt', 'r'):
                    original_ciphertext += line
            except FileNotFoundError as e:
                print(repr(e))
                sys.exit(2)
            else:
                iv = bytes([0] * 16)
                key_text = "YELLOW SUBMARINE"
                try:
                    key = key_text.encode()
                    ciphertext = iv + base64.b64decode(original_ciphertext.encode())
                except binascii.Error as e:
                    print("Decoding Error: " + str(e))
                    sys.exit(2)
                else:
                    plaintext = CBC_Decryptor(key, ciphertext)
                    print("Plaintext is: " + plaintext.decode())
        if opt == '-m':
            if arg == 'E':
                try:
                    plaintext = args[0].encode()
                    key = args[1].encode()
                    iv = args[2].encode()
                except binascii.Error as e:
                    print("Decoding Error: " + str(e))
                    sys.exit(2)
                except IndexError as e:
                    print("Encryption must provide IV!")
                    sys.exit(2)
                else:
                    ciphertext = CBC_Encryptor(key, plaintext)
                    print("Ciphertext is: " + ciphertext.decode())
            if arg == 'D':
                try:
                    ciphertext_input = args[0].encode()
                    key = args[1].encode()
                    if len(args > 2):
                        iv = args[2].encode()
                except binascii.Error as e:
                    print("Decoding Error: " + str(e))
                    sys.exit(2)
                else:
                    if iv:
                        ciphertext = iv + ciphertext_input
                    plaintext = CBC_Decryptor(key, ciphertext)
                    print("Plaintext is: " + plaintext.decode())


if __name__ == "__main__":
    main(sys.argv[1:])