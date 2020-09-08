import sys
import codecs
import getopt
import binascii
import secrets

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend

from challenge_08 import split_by_length


def left_rotate(num, rotate_length):
    return ((num << rotate_length) | (num >> (32 - rotate_length))) & 0xFFFFFFFF

class SHA1_prefix_MAC(object):
    """
    SHA1_prefix_MAC
    Implementing SHA1 for MAC, with the ability to set internal chunks
    All intergers are in big-endian    
    """

    def __init__(self, key):
        super(SHA1_prefix_MAC, self).__init__()
        self.key = key

    def preprocess(self, text):

        if type(text) != bytes:
            text = text.encode()

        ml = len(text) * 8

        # Preprocessing the input by the manipulating the binary string of text
        if ml == 0:
            text_bin_string = ''
        else:
            text_bin_string = bin(int.from_bytes(text, 'big'))[2:]

        # bin(int.from_bytes()) truncates preceding zeroes, fixed as below, but better use struct.unpack next time
        while len(text_bin_string) % 8 != 0:
            text_bin_string = '0' + text_bin_string
        text_bin_string = text_bin_string + '1'
        while len(text_bin_string) % 512 != 448:
            text_bin_string += '0'

        # Set the last 64 bit as the original text length ml
        text_bin_string = text_bin_string + bin(ml)[2:].zfill(64)

        return text_bin_string

    def calculate_hashing(self, bin_string):

        bin_string_chunks = split_by_length(bin_string, 512)
        for chunk in bin_string_chunks:
            words = list(map(lambda x: int(x, 2), split_by_length(chunk, 32)))
            for i in range(16, 80):
                t = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]
                words.append(left_rotate(t, 1))

            a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4

            for j in range(80):
                if j in range(20):
                    '''
                    f = (b & c) | ((~b) & d) in the pesudocode from Wiki
                    ~ seems weird though the reault is still correct
                    Use the following substitution
                    '''
                    f = (((c ^ d) & b) ^ d)
                    k = 0x5A827999
                elif j in range(20, 40):
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif j in range(40, 60):
                    f = (b & c) | (b & d) | (c & d) 
                    k = 0x8F1BBCDC
                elif j in range(60, 80):
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = (left_rotate(a, 5) + f + e + k + words[j]) & 0xFFFFFFFF
                e = d
                d = c
                c = left_rotate(b, 30)
                b = a
                a = temp

            self.h0 = (self.h0 + a) & 0xFFFFFFFF
            self.h1 = (self.h1 + b) & 0xFFFFFFFF 
            self.h2 = (self.h2 + c) & 0xFFFFFFFF
            self.h3 = (self.h3 + d) & 0xFFFFFFFF
            self.h4 = (self.h4 + e) & 0xFFFFFFFF

        hash_value = list(map(lambda x: x.to_bytes(4, 'big'), [self.h0, self.h1, self.h2, self.h3, self.h4]))
        return b''.join(hash_value)

    def set_chunk(self, a, b, c, d, e):

        self.h0, self.h1, self.h2, self.h3, self.h4 = a, b, c, d, e

    def MAC_text(self, text):
        text = self.key + text
        self.set_chunk(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
        text_bin_string = self.preprocess(text)
        return self.calculate_hashing(text_bin_string)

    def verify(self, text, hash_value):

        return (self.MAC_text(text) == hash_value)

def prefix_SHA1_MAC(key, text):

    if type(text) != bytes:
        text = text.encode()

    backend = default_backend()
    digest = Hash(SHA1(), backend=backend)
    digest.update(key + text)

    return digest.finalize()


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_28.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_28.py [-h | --help]')
            print('Challenge 28: Implement a SHA-1 keyed MAC')
            sys.exit()

    key = secrets.token_bytes(16)
    text = b"YELLOW SUBMARINE"
    correct_MAC = prefix_SHA1_MAC(key, text)

    # Verifying the implementation
    MAC_generator = SHA1_prefix_MAC(key)
    testing_MAC = MAC_generator.MAC_text(text)
    print("Implementation successful? " + str(bool(testing_MAC == correct_MAC)))

    
    new_text = text[:-10] + b" SUB MARINE"
    print("Original text is " + text.decode())
    print("New text is " + new_text.decode())
    print("Same MAC? " + str(MAC_generator.verify(new_text, testing_MAC)))

    for x in range(2 ** 24):
        trial_key = secrets.token_bytes(16)
        trial_text = b"YELLOW SUBMARINE"
        trial_MAC = SHA1_prefix_MAC(trial_key).MAC_text(trial_text)
        if (trial_MAC == testing_MAC) and (trial_key != key):
            print(b"Found second key for this input and MAC! " + trial_key)
    print("Couldn't find second key for this input and MAC!")

if __name__ == "__main__":
    main(sys.argv[1:])