import argparse

from challenge_33 import power_mod
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_big_primes(e, length):
    backend = default_backend()
    private_key = rsa.generate_private_key(public_exponent=e, key_size=length, backend=backend)
    p, q = private_key.private_numbers().p, private_key.private_numbers().q
    return p, q


def invmod(a, n):
    mod_base = n
    x, y = 0, 1
    while a != 0:
        n, a, x, y = a, n % a, y, x - y * (n // a)
    while x < 0:
        x += mod_base
    if x == 1:
        # No inverse
        return None
    else:
        return x


def simple_rsa_keygen(p, q, e):
    n = p * q
    et = (p - 1) * (q - 1)
    d = invmod(e, et)
    pk = (e, n)
    sk = (d, n)
    return pk, sk


def simple_rsa_encrypt(pk, m):
    e, n = pk
    return power_mod(m, e, n)


def simple_rsa_decrypt(sk, c):
    d, n = sk
    return power_mod(c, d, n)


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()

    print("Challenge 39: Implement RSA")

    def rsa_demonstration(p, q, m):
        pk, sk = simple_rsa_keygen(p, q, e=3)
        print("Try encrypting number {}".format(m))
        c = simple_rsa_encrypt(pk, m)
        print("Encryption is {}".format(c))
        print("Implementation success? {}\n".format(m == simple_rsa_decrypt(sk, c)))

    rsa_demonstration(11, 17, 42)
    print("Repeat with big primes")
    large_p, large_q = generate_big_primes(3, 2048)
    rsa_demonstration(large_p, large_q, 42)
    print("Let's encrypt some random message for fun!")
    msg = input("Input message to send: ")
    msg_bytes = msg.encode()
    msg_num = int.from_bytes(msg_bytes, 'big')
    rsa_demonstration(large_p, large_q, msg_num)


if __name__ == "__main__":
    main()
