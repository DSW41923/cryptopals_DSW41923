import argparse
import heapq
import secrets
import string
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
from typing import Callable
from challenge_10 import cbc_encryptor


BASE64_CHARARCTERS = string.digits + string.ascii_letters + '+/='
PADDING_CHARACTERS = '!@#$%^&*()-`~[]}{'


def simple_RC4_encryptor(key: bytes, plaintext: bytes) -> bytes:
    # Prepare encryptor
    backend = default_backend()
    stream_cipher = Cipher(algorithms.ARC4(key), mode=None, backend=backend)
    stream_encryptor = stream_cipher.encryptor()
    return stream_encryptor.update(plaintext)


def compression_oracle(request_str: str, cipher: Callable) -> int:
    compressed_request_bytes = zlib.compress(request_str.encode())
    key = secrets.token_bytes(16)
    if cipher == cbc_encryptor:
        iv = secrets.token_bytes(16)
        return len(cipher(key, compressed_request_bytes, iv))

    if cipher == simple_RC4_encryptor:
        return len(cipher(key, compressed_request_bytes))

    raise NotImplementedError


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 51: Compression Ratio Side-Channel Attacks")
    request_base = '''POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: {}
{}'''
    trial_base = 'sessionid='
    print("Attacking under RC4 stream cipher encryption")
    trials = [(compression_oracle(request_base.format(len(trial_base), trial_base), simple_RC4_encryptor), trial_base)]
    while trials:
        trial_result, trial = heapq.heappop(trials)
        for char in BASE64_CHARARCTERS:
            new_trial = trial + char
            new_trial_result = compression_oracle(request_base.format(len(new_trial), new_trial),
                                                  simple_RC4_encryptor)
            heapq.heappush(trials, (new_trial_result, new_trial))

        print("Session ID is {}".format(trials[0][-1]), end='\r')
        if len(trials[0][1]) == 54:
            print()
            print("Attack success? {}".format(trials[0][-1] in request_base))
            break

    print("Attacking under AES-CBC encryption")
    trials = [(compression_oracle(request_base.format(len(trial_base), trial_base), cbc_encryptor), 10, trial_base)]
    while trials:
        trial_result, trial_len, trial_str = heapq.heappop(trials)
        new_trial_append = ''
        for j in range(16):
            new_trials = []
            for char in BASE64_CHARARCTERS:
                new_trial = trial_str + char
                new_trial_result = compression_oracle(request_base.format(len(new_trial), new_trial_append + new_trial),
                                                      cbc_encryptor)
                heapq.heappush(new_trials, (new_trial_result, len(new_trial), new_trial))

            if new_trials[0][0] != new_trials[-1][0]:
                heapq.heappush(trials, new_trials[0])
                break

            new_trial_append += secrets.choice(PADDING_CHARACTERS)
            if j == 15:
                for new_trial in new_trials:
                    heapq.heappush(trials, new_trial)

        print("Session ID is {}".format(trials[0][-1]), end='\r')
        if len(trials[0][-1]) == 54:
            print()
            print("Attack success? {}".format(trials[0][-1] in request_base))
            break


if __name__ == "__main__":
    main()
