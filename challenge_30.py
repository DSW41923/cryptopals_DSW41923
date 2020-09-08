import sys
import codecs
import getopt
import binascii
import secrets

from challenge_08 import split_by_length
from challenge_28 import left_rotate

class MD4_prefix_MAC(object):
    """
    MD4_prefix_MAC
    Implementing MD4 for MAC, with the ability to set internal chunks
    All intergers are in big-endian    
    """

    def __init__(self, key):
        super(MD4_prefix_MAC, self).__init__()
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

        # bin(int.from_bytes()) truncates preceding zeroes, fixed as below
        while len(text_bin_string) % 8 != 0:
            text_bin_string = '0' + text_bin_string
        text_bin_string = text_bin_string + '1'
        while len(text_bin_string) % 512 != 448:
            text_bin_string += '0'

        # Append original text length ml
        ml_bin = bin(int.from_bytes(ml.to_bytes(8, 'little'), 'big'))[2:].zfill(64)
        text_bin_string = text_bin_string + ml_bin

        return text_bin_string

    def calculate_hashing(self, bin_string):

        bin_string_chunks = split_by_length(bin_string, 512)
        for chunk in bin_string_chunks:
            words = list(map(lambda x: int.from_bytes(int(x, 2).to_bytes(4, 'big'), 'little'), split_by_length(chunk, 32)))
            h = [self.h0, self.h1, self.h2, self.h3]

            for n in range(48):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))

                if n in range(16):
                    F = (h[j] & h[k]) | ((~h[j]) & h[l])
                    L = 0x00000000
                    X = [3, 7, 11, 19]
                    Ki = range(16)
                elif n in range(16, 32):
                    F = (h[j] & h[k]) | (h[j] & h[l]) | (h[k] & h[l]) 
                    L = 0x5A827999
                    X = [3, 5, 9, 13]
                    Ki = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
                elif n in range(32, 48):
                    F = h[j] ^ h[k] ^ h[l]
                    L = 0x6ED9EBA1
                    X = [3, 9, 11, 15]
                    Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
                
                K = Ki[n % 16]
                S = X[n % 4]
                hn = (h[i] + F + words[K] + L) & 0xFFFFFFFF
                h[i] = left_rotate(hn, S)

            self.h0 = (self.h0 + h[0]) & 0xFFFFFFFF
            self.h1 = (self.h1 + h[1]) & 0xFFFFFFFF 
            self.h2 = (self.h2 + h[2]) & 0xFFFFFFFF
            self.h3 = (self.h3 + h[3]) & 0xFFFFFFFF

        hash_value = list(map(lambda x: x.to_bytes(4, 'little'), [self.h0, self.h1, self.h2, self.h3]))
        return b''.join(hash_value)

    def set_chunk(self, a, b, c, d):

        self.h0, self.h1, self.h2, self.h3 = a, b, c, d

    def MAC_text(self, text):

        text = self.key + text
        self.set_chunk(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
        text_bin_string = self.preprocess(text)
        return self.calculate_hashing(text_bin_string)

    def verify(self, text, hash_value):

        return (self.MAC_text(text) == hash_value)



def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_30.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_30.py [-h | --help]')
            print('Challenge 30: Break an MD4 keyed MAC using length extension')
            sys.exit()

    # Verify MD4 Implemetation
    testing_text = [b"", b"a", b"abc", b"message digest",
        b"abcdefghijklmnopqrstuvwxyz",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"]
    verifying_hash = ["31d6cfe0d16ae931b73c59d7e0c089c0",
        "bde52cb31de33e46245e05fbdbd6fb24",
        "a448017aaf21d8525fc10ae87aa6729d",
        "d9130a8164549fe818874806e1c7014b",
        "d79e1c308aa5bbcdeea8ed63df412da9",
        "043f8582f241db351ce627e153e7f0e4",
        "e33b4ddc9c38f2199c3e7b164fcc0536"]
    verifying_MAC = MD4_prefix_MAC(b'')
    for text, hash_value in zip(testing_text, verifying_hash):
        if not verifying_MAC.verify(text, bytes.fromhex(hash_value)):
            print("Implementation Fail at text: " + text.decode())
            sys.exit()
    print("Successful Implementation!")

    # Breaking using length extension
    key = secrets.token_bytes(16)
    text = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    target = b';admin=true'

    MAC_generator = MD4_prefix_MAC(key)
    original_MAC = MAC_generator.MAC_text(text)
    new_states = tuple(map(lambda x: int.from_bytes(int(x, 16).to_bytes(4, 'big'), 'little'), split_by_length(original_MAC.hex(), 8)))

    for x in range(2 ** 64 - len(text)):

        # Getting original padding
        trial_text = b'A' * x + text
        original_padded_text_bin = MAC_generator.preprocess(trial_text)
        original_padded_text = int(original_padded_text_bin, 2).to_bytes(len(original_padded_text_bin) // 8, byteorder='big')
        trial_mali_text = original_padded_text + target

        # Caculating hash from new blocks with states provided
        MAC_generator.set_chunk(*new_states)
        padded_trial_mali_text_bin = MAC_generator.preprocess(trial_mali_text)
        mali_MAC = MAC_generator.calculate_hashing(padded_trial_mali_text_bin[1024:])
        if MAC_generator.verify(trial_mali_text[x:], mali_MAC):
            print("Got It!")
            print(b"Desired extended text is: " + trial_mali_text[x:])
            break

if __name__ == "__main__":
    main(sys.argv[1:])