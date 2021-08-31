import argparse

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend
from challenge_33 import power_mod
from challenge_39 import invmod

P = int("800000000000000089e1855218a0e7dac38136ffafa72eda7"
        "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"
        "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"
        "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"
        "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"
        "1a584471bb1", 16)

Q = int("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)

G = int("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"
        "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"
        "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"
        "0f5b64c36b625a097f1651fe775323556fe00b3608c887892"
        "878480e99041be601a62166ca6894bdd41a7054ec89f756ba"
        "9fc95302291", 16)

Y = int("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4"
        "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004"
        "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed"
        "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b"
        "bb283e6633451e535c45513b2d33c99ea17", 16)


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 43: DSA key recovery from nonce")

    msg = b'''For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
'''
    hashed_msg_hex = "d2d0714f014a9784047eaeccf956520045c45265"
    backend = default_backend()
    digest = Hash(SHA1(), backend=backend)
    digest.update(msg)
    print("Message = {}".format(msg))
    print("Is the digest of the message correct? {}".format(digest.finalize().hex() == hashed_msg_hex))
    msg_num = int(hashed_msg_hex, 16)
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    for k in range(2 ** 16):
        new_r = power_mod(G, k, P) % Q
        if r == new_r:
            x = (s * k - msg_num) * invmod(r, Q) % Q
            backend = default_backend()
            digest = Hash(SHA1(), backend=backend)
            digest.update(hex(x)[2:].encode())
            print("Found private key x = {}".format(x))
            print("Is the digest of the private key correct? {}".format(
                digest.finalize().hex() == '0954edd5e0afe5542a4adf012611a91912a3ec16'))
            break


if __name__ == "__main__":
    main()
