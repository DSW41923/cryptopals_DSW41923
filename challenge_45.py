import argparse
import secrets

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend
from typing import Tuple
from challenge_33 import power_mod
from challenge_39 import invmod
from challenge_43 import P, Q, G
from challenge_44 import Y


X = 1379952329417023174824742221952501647027600451162


def simple_dsa_sign(digest_num: int, g: int) -> Tuple[int, int]:
    pre_k = secrets.choice(list(range(2 ** 16)))
    k = power_mod(G, pre_k, Q)
    r = power_mod(g, k, P) % Q
    s = invmod(k, Q) * (digest_num + X * r) % Q
    return r, s


def simple_dsa_verify(digest_num: int, signature: Tuple[int, int], g: int) -> bool:
    r, s = signature
    assert r < Q and s < Q
    w = invmod(s, Q)
    u1 = digest_num * w % Q
    u2 = r * w % Q
    v = power_mod(g, u1, P) * power_mod(Y, u2, P) % Q
    return v == r


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 45: DSA parameter tampering")
    msg1 = b'Hello, world'
    msg2 = b'Goodbye, world'
    backend = default_backend()
    digest1 = Hash(SHA1(), backend=backend)
    digest1.update(msg1)
    hashed_msg1 = digest1.finalize()
    hashed_msg1_num = int(hashed_msg1.hex(), 16)
    digest2 = Hash(SHA1(), backend=backend)
    digest2.update(msg2)
    hashed_msg2 = digest2.finalize()
    hashed_msg2_num = int(hashed_msg2.hex(), 16)

    g_candidates = [0, P+1]
    for index, g in enumerate(g_candidates):
        signature1 = simple_dsa_sign(hashed_msg1_num, g)
        print("Signature of msg {}(byte str) with g={} is {}".format(msg1, g, signature1))
        signature2 = simple_dsa_sign(hashed_msg2_num, g)
        print("Signature of msg {}(byte str) with g={} is {}".format(msg2, g, signature2))
        print("Verifing digest of msg1 {}(in hex) with signature of msg2 {}\nIs the signature valid? {}".format(
            hashed_msg1.hex(), signature2, simple_dsa_verify(hashed_msg1_num, signature2, g)))
        print("Verifing digest of msg2 {}(in hex) with signature of msg1 {}\nIs the signature valid? {}".format(
            hashed_msg2.hex(), signature1, simple_dsa_verify(hashed_msg2_num, signature1, g)))

        if index == 1:
            print("Generating Magic Signature...")
            z = secrets.choice(range(2 ** 16))
            magic_r = power_mod(Y, z, P) % Q
            magic_s = magic_r * invmod(z, Q) % Q
            magic_signature = (magic_r, magic_s)
            print("Verifing digest of msg1 {}(in hex) with magic signature {}\nIs the signature valid? {}".format(
                hashed_msg1.hex(), magic_signature, simple_dsa_verify(hashed_msg1_num, magic_signature, g)))
            print("Verifing digest of msg2 {}(in hex) with magic signature {}\nIs the signature valid? {}".format(
                hashed_msg2.hex(), magic_signature, simple_dsa_verify(hashed_msg2_num, magic_signature, g)))


if __name__ == "__main__":
    main()
