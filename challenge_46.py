import argparse
import codecs
import string
import time

from typing import Tuple
from challenge_39 import simple_rsa_keygen, generate_big_primes, simple_rsa_decrypt, simple_rsa_encrypt


def parity_oracle(sk: Tuple[int, int], ct: int) -> bool:
    pt = simple_rsa_decrypt(sk, ct)
    return pt % 2 == 1


def print_len(m: bytes) -> int:
    length = 0
    for char in m:
        length += 1 if char in bytes(string.printable, 'ascii') else 4
    return length


def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 46: RSA parity oracle")

    p, q = generate_big_primes(e=3, length=1024)
    pk, sk = simple_rsa_keygen(p, q, e=3)
    e, n = pk
    input_string = b"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="

    pt_bytes = codecs.decode(input_string, encoding='base64')
    pt_num = int.from_bytes(pt_bytes, 'big')
    print("Secretly decode input into number as {}".format(pt_num))
    ct_num = simple_rsa_encrypt(pk, pt_num)

    pt_num_base, ct_trial = 0, ct_num
    lower_bound, upper_bound = 0, n
    print("Cracking with oracle...")
    time.sleep(1)
    for _ in range(n):
        ct_trial = (ct_trial * 2 ** e) % n
        if parity_oracle(sk, ct_trial):
            lower_bound = (lower_bound + upper_bound) // 2 - 1
        else:
            upper_bound = (lower_bound + upper_bound) // 2 + 1

        temp_result = int_to_bytes(upper_bound)
        # Only print results with better look
        if print_len(temp_result) < 180:
            print(temp_result, end='\x1b[K\r')
        if upper_bound - lower_bound < 256:
            pt_num_base = (upper_bound // 256) << 8
            print()
            break

    # Use antoher way to deal with the precision problem of the last byte
    print("Finding last byte...")
    for i in range(256):
        pt_num_candidate = pt_num_base + i
        if simple_rsa_encrypt(pk, pt_num_candidate) == ct_num:
            print("Plaintext in number is {}".format(pt_num_candidate))
            print("Cracked plaintext is {}".format(int_to_bytes(pt_num_candidate)))
            print("Is plaintext correct? {}".format(int_to_bytes(pt_num_candidate) == pt_bytes))
            break


if __name__ == "__main__":
    main()
