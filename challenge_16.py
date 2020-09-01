import sys
import getopt
import binascii
import secrets

from challenge_02 import bytestrxor
from challenge_10 import CBC_Encryptor, CBC_Decryptor

CBC_KEY = secrets.token_bytes(16)

def encrypt_data_CBC(text):
    quoted_text = text.replace(";", "\\;").replace("=", "\\=")
    plaintext = "comment1=cooking%20MCs;userdata={};comment2=%20like%20a%20pound%20of%20bacon".format(quoted_text)
    iv = secrets.token_bytes(16)
    ciphertext = CBC_Encryptor(CBC_KEY, plaintext.encode(), iv)
    return ciphertext

def decrypt_and_detect(ciphertext, text=b";admin=true;"):
    plaintext = CBC_Decryptor(CBC_KEY, ciphertext)
    if type(text) != bytes:
        text = text.encode()
    return text in plaintext


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_16.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_16.py [-h | --help]')
            print('Challenge 16: CBC bitflipping attacks')
            sys.exit()

    # Create a simple ciphertext
    data = 'A' * 16
    ciphertext = encrypt_data_CBC(data)
    print("Is there \";admin=true;\" detected? " + str(decrypt_and_detect(ciphertext)))
    print("Attacking...")

    # Generate text for modification
    target_text = b";admin=true;"
    evil_text = bytestrxor(target_text, b'A' * len(target_text))
    evil_block = bytestrxor(ciphertext[32:48][:len(target_text)], evil_text) + ciphertext[32:48][len(target_text):]
    new_ciphertext = ciphertext[:32] + evil_block + ciphertext[48:]
    print("Is there \";admin=true;\" detected? " + str(decrypt_and_detect(new_ciphertext)))


if __name__ == "__main__":
    main(sys.argv[1:])