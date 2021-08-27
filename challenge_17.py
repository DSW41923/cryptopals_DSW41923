import sys
import getopt
import secrets
import base64

from challenge_02 import bytestrxor
from challenge_08 import split_by_length
from challenge_10 import cbc_encryptor, cbc_decryptor
from challenge_15 import verify_padding

CBC_KEY = secrets.token_bytes(16)


def encrypt_in_cbc(plaintext):
    iv = secrets.token_bytes(16)
    ciphertext = cbc_encryptor(CBC_KEY, plaintext, iv)
    return ciphertext


def decrypt_and_verify_padding(ciphertext):
    plaintext = cbc_decryptor(CBC_KEY, ciphertext)
    try:
        return verify_padding(plaintext[-16:], 16)
    except ValueError:
        return False


# noinspection SpellCheckingInspection
def main(argv):
    try:
        opts, args = getopt.getopt(argv, "h:", ["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_17.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_17.py [-h | --help]')
            print('Challenge 17: The CBC padding oracle')
            sys.exit()

    data = [
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ]
    plaintext = base64.b64decode(secrets.choice(data))

    # Create ciphertext to decrypt
    ciphertext = encrypt_in_cbc(plaintext)
    ciphertext_blocks = split_by_length(ciphertext, 16)
    result = b''
    for iv, target in zip(ciphertext_blocks[:-1], ciphertext_blocks[1:]):
        block_result = b''
        for j in range(1, 17):

            # Avoid trying the original padding when decrypting last byte
            trial_start = 0
            if j == 1:
                trial_start = 1
            # Try all possible byte until the padding is correct
            for k in range(trial_start, 256):
                guessing_byte = iv[-j] ^ k
                new_iv = iv[:-j] + bytes([guessing_byte])
                if block_result:
                    forged_padding = bytestrxor(bytes([j] * (j - 1)), bytestrxor(iv[-j + 1:], block_result))
                    new_iv += forged_padding
                if bool(decrypt_and_verify_padding(new_iv + target)):
                    plaintext_byte = bytes([j ^ k])
                    block_result = plaintext_byte + block_result
                    break
        result += block_result

    print(b"Decrypted result is: " + result)


if __name__ == "__main__":
    main(sys.argv[1:])
