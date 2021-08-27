import argparse
import math

from typing import Iterable, Tuple
from challenge_39 import invmod, generate_big_primes, simple_rsa_encrypt


def crt_solver(residues: Iterable[Tuple[int, int]]) -> int:
    n_all = math.prod([r[1] for r in residues])
    result = 0
    for r, n in residues:
        result += r * (n_all // n) * invmod(n_all // n, n)
    return result % n_all


def cubic_root_bignum(x):
    """
    Finds y, the integer component of the cubic root of x, such that y ** n <= x < (y + 1) ** n.
    """
    high = 1
    while high ** 3 <= x:
        high *= 2
    low = high // 2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid ** 3 < x:
            low = mid
        elif high > mid and mid ** 3 > x:
            high = mid
        else:
            return mid


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()

    print("Challenge 40: Implement an E=3 RSA Broadcast attack")
    pks = []
    for _ in range(3):
        p, q = generate_big_primes(e=3, length=2048)
        pks.append((3, p * q))
    msg = input("Input message to send: ")
    msg_bytes = msg.encode()
    msg_num = int.from_bytes(msg_bytes, 'big')
    if msg_num >= max([pk[1] for pk in pks]):
        print("Message too big! RSA may fail!")
    encrypted_msgs = [simple_rsa_encrypt(pk, msg_num) for pk in pks]
    residues = list(zip(encrypted_msgs, [pk[1] for pk in pks]))
    result = crt_solver(residues)
    print("Original message in numeric form is {}".format(msg_num))
    print("Cracked result is {}".format(cubic_root_bignum(result)))
    if cubic_root_bignum(result) == msg_num:
        print("Attack success!")
    else:
        print("Something went wrong!")


if __name__ == "__main__":
    main()
