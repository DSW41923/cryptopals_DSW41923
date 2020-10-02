import sys
import getopt
import secrets

from challenge_18 import ctr_cryptor
from challenge_25 import edit


NONCE = bytes([0] * 8)
CTR_KEY = secrets.token_bytes(16)

def encrypt_data_ctr(text):
    quoted_text = text.replace(";", "\\;").replace("=", "\\=")
    plaintext = "comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon".format(quoted_text)
    ciphertext = ctr_cryptor(plaintext.encode(), CTR_KEY, NONCE)
    return ciphertext

def decrypt_and_detect(ciphertext, text=b";admin=true;"):
    plaintext = ctr_cryptor(ciphertext, CTR_KEY, NONCE)
    if type(text) != bytes:
        text = text.encode()
    return text in plaintext


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_26.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_26.py [-h | --help]')
            print('Challenge 26: CTR bitflipping')
            sys.exit()

    # Create a simple ciphertext
    data = 'A' * 16
    ciphertext = encrypt_data_ctr(data)
    print("Is there \";admin=true;\" detected? " + str(decrypt_and_detect(ciphertext)))
    print("Attacking...")

    # Generate text for modification
    target_text = b";admin=true;"
    new_ciphertext = edit(ciphertext, CTR_KEY, 32, target_text)
    print("Is there \";admin=true;\" detected? " + str(decrypt_and_detect(new_ciphertext)))


if __name__ == "__main__":
    main(sys.argv[1:])