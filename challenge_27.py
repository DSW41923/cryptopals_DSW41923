import sys
import getopt
import secrets

from challenge_02 import bytestrxor
from challenge_08 import split_by_length
from challenge_10 import cbc_encryptor, cbc_decryptor


CBC_KEY = secrets.token_bytes(16)


def encrypt_checked_data_cbc(plaintext):
    if type(plaintext) != bytes:
        plaintext = plaintext.encode()

    for byte in plaintext:
        if byte > 127:
            raise ValueError(b"High ASCII Values Detected in plaintext!! : " + plaintext)

    return cbc_encryptor(CBC_KEY, plaintext, CBC_KEY)

def decrypt_and_check(ciphertext):
    plaintext = cbc_decryptor(CBC_KEY, ciphertext)
    for byte in plaintext:
        if byte > 127:
            raise ValueError(b"High ASCII Values Detected in plaintext!! : " + plaintext)
    return plaintext


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_27.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_27.py [-h | --help]')
            print('Challenge 27: Recover the key from CBC with IV=Key')
            sys.exit()

    # Create a simple ciphertext
    plaintext = 'YELLOW SUBMARINE' * 16
    ciphertext = encrypt_checked_data_cbc(plaintext)
    print("Is the encryption and decryption successful? " + str(bool(decrypt_and_check(ciphertext))))
    # print("Attacking...")

    # Attacking
    ciphertext_blocks = split_by_length(ciphertext, 16)
    new_ciphertext = ciphertext_blocks[0:2] + [bytes([0] * 16)] + ciphertext_blocks[1:]
    new_ciphertext = b"".join(new_ciphertext)
    try:
        new_plaintext = decrypt_and_check(new_ciphertext)
    except ValueError as e:
        new_plaintext = eval(repr(e)[11:-1])[44:]
    new_plaintext_blocks = split_by_length(new_plaintext, 16)
    key_recovered = bytestrxor(new_plaintext_blocks[0], new_plaintext_blocks[2])
    print(b"Key recovered as: " + key_recovered)
    print("Is the recovered key correct? " + str(key_recovered == CBC_KEY))


if __name__ == "__main__":
    main(sys.argv[1:])