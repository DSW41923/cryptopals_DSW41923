import argparse

from challenge_39 import simple_rsa_keygen, simple_rsa_encrypt, generate_big_primes
from challenge_46 import int_to_bytes
from challenge_47 import bleichenbacher_attack, simple_padding, RSAOracle

KEY_LENGTH = 768
P, Q = generate_big_primes(e=3, length=KEY_LENGTH)
PK, SK = simple_rsa_keygen(P, Q, e=3)


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 48: Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)")

    message = b'kick it, CC'
    block_length = PK[1].bit_length() // 8 + 1
    oracle = RSAOracle(SK)
    m = simple_padding(message, block_length)
    print("Message to be cracked (in hex, padded) is {}".format(m.hex()))
    m_num = int.from_bytes(m, 'big')
    c_num = simple_rsa_encrypt(PK, m_num)
    print("Ciphertext to be used (in number) is {}".format(c_num))

    cracked_m = bleichenbacher_attack(c_num, block_length, PK, oracle)
    print("Cracked message (in hex) is {}".format(int_to_bytes(cracked_m, block_length).hex()))
    print("Is the attack success?(i.e. cracked message == original padded message) {}".format(cracked_m == m_num))


if __name__ == "__main__":
    main()
