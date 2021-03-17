import sys
import getopt
import secrets
import re

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from challenge_08 import split_by_length
from challenge_09 import padding_to_length


def parse_pseudo_cookie_text(text):
    email_captured = re.search(r'email=(.+@[a-zA-Z.]+)&', text)
    email = email_captured.group(1)
    no_email_text = text.replace(email_captured.group(0), '')
    uid = re.search(r'uid=(\d+)&', no_email_text).group(1)
    role = re.search(r'role=(\w+)', no_email_text).group(1)
    parsed = {
        'email': email,
        'uid': int(uid),
        'role': role
    }
    return parsed

def new_profile(email):
    email_domain = email.split('@')[-1]
    if ('&' in email_domain) or ('=' in email_domain):
        print("Invalid Email Format!")
        return ''

    profile = {
        'email': email,
        'uid': 10,
        'role': 'user'
    }
    return encode_profile(profile)

def encode_profile(profile):
    email = profile['email']
    uid = profile['uid']
    role = profile['role']
    return 'email={}&uid={}&role={}'.format(email, str(uid), role)

def encrypt_profile(key, plaintext):
    plaintext = pad_plaintext(plaintext, 16)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def decrypt_to_profile(key, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return parse_pseudo_cookie_text(plaintext.decode())

def pad_plaintext(plaintext, block_length):
    plaintext_blocks = split_by_length(plaintext, block_length)
    if len(plaintext_blocks[-1]) < block_length:
        plaintext_blocks[-1] = padding_to_length(plaintext_blocks[-1], block_length)
    return b''.join(plaintext_blocks)


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_13.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_13.py [-h | --help]')
            print('Challenge 13: ECB cut-and-paste')
            sys.exit()

    email = "foo@bar.com"
    # Get valid ciphertext
    key = secrets.token_bytes(16)
    profile_text = new_profile(email)
    profile_encryption = encrypt_profile(key, profile_text.encode())

    # Prepare an evil profile with the last block to be replaced
    evil_profile_text = profile_text
    for x in range(1, 5):
        evil_profile_text = new_profile("A" * x + "foo@bar.com")
        evil_profile_text_blocks = split_by_length(evil_profile_text, 16)
        if evil_profile_text_blocks[-1] == 'user':
            break
    encrypted_evil_profile = encrypt_profile(key, evil_profile_text.encode())

    # Replacing the last block
    encrypted_replacer = encrypt_profile(key, b"admin")
    tampered_profile_encryption = encrypted_evil_profile[:-16] + encrypted_replacer
    tampered_profile = decrypt_to_profile(key, tampered_profile_encryption)

    # Print both profiles to show the difference
    original_profile = decrypt_to_profile(key, profile_encryption)
    print("Original profile is " + str(original_profile))
    print("Tampered profile is " + str(tampered_profile))


if __name__ == "__main__":
    main(sys.argv[1:])
