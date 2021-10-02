import argparse
import random
import secrets

from typing import Tuple, List
from challenge_33 import power_mod
from challenge_39 import simple_rsa_keygen, simple_rsa_decrypt, simple_rsa_encrypt
from challenge_46 import int_to_bytes


class RSAOracle(object):
    def __init__(self, sk: Tuple[int, int]):
        self.sk_info = sk

    def oracle(self, ciphertext: bytes) -> bool:
        pt = simple_rsa_decrypt(self.sk_info, int.from_bytes(ciphertext, 'big'))
        pt_bytes = int_to_bytes(pt, self.sk_info[1].bit_length() // 8 + 1)
        return pt_bytes[0] == 0 and pt_bytes[1] == 2


def rabinMiller(n: int) -> bool:
    s = n - 1
    t = 0
    while s & 1 == 0:
        s = s // 2
        t += 1
    k = 0
    while k < 128:
        a = random.randrange(2, n - 1)
        v = power_mod(a, s, n)
        if v != 1:
            i = 0
            while v != (n - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % n
        k += 2
    return True


def is_prime(num: int) -> bool:
    # Code from: https://langui.sh/2009/03/07/generating-very-large-primes/
    # Taking num modulo each lowPrime (all primes under 1000) to remove a huge chunk of composite numbers
    # Then use Rabin-Miller Test
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101,
                 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199,
                 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
                 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443,
                 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577,
                 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
                 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839,
                 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983,
                 991, 997]
    if num > 1:
        if num in lowPrimes:
            return True

        if (num % 6) in [1, 5]:
            for p in lowPrimes:
                if (num % p) == 0:
                    return False
            return rabinMiller(num)
    return False


def generate_small_prime(e: int, length: int):
    p, q = 1, 1
    while not is_prime(p) or (p - 1) % e == 0:
        p = secrets.randbits(length)
    while not is_prime(q) or (q - 1) % e == 0:
        q = secrets.randbits(length)
    return p, q


def simple_padding(message: bytes, block_length: int, padding="PKCS1.5") -> bytes:
    if padding == "PKCS1.5":
        padding_length = block_length - 3 - len(message)
        padded_payload = b'\x00\x02%b\x00%b' % (secrets.token_bytes(padding_length), message)
        return padded_payload
    else:
        raise NotImplementedError


def union_intervals(intervals: List[Tuple[int, int]], new_interval: Tuple[int, int]):
    new_a, new_b = new_interval
    for i, (a, b) in enumerate(intervals):
        if not (b < new_a or a > new_b):
            new_a = min(new_a, a)
            new_b = max(new_b, b)
            intervals[i] = new_a, new_b
            return

    intervals.append(new_interval)


def ceil_division(a: int, b: int) -> int:
    r = a // b
    while r * b < a < (r+1) * b:
        r += 1
    return r


def floor_division(a: int, b: int) -> int:
    r = a // b
    while (r-1) * b < a < r * b:
        r -= 1
    return r


def bleichenbacher_attack(c: int, block_length: int, pk_info: Tuple[int, int], rsa_oracle: RSAOracle) -> int:
    e, n = pk_info
    b = 2 ** (8 * (block_length - 2))
    intervals, c_0, s_0, i = [(2 * b, 3 * b - 1)], c, 1, 1
    s_i = s_0

    print("Cracking m", end='', flush=True)
    while len(intervals) > 1 or intervals[0][1] - intervals[0][0] > 0:
        print(".", end='', flush=True)

        new_intervals = []
        if i == 1:
            s = ceil_division(n, (3 * b))
            while s < n:
                trial_c = (c_0 * power_mod(s, e, n)) % n
                if rsa_oracle.oracle(int_to_bytes(trial_c)):
                    s_i = s
                    break
                s += 1
        else:
            if len(intervals) > 1:
                s = s_i + 1
                while s < n:
                    trial_c = (c_0 * power_mod(s, e, n)) % n
                    if rsa_oracle.oracle(int_to_bytes(trial_c)):
                        s_i = s
                        break
                    s += 1
            else:
                r = ceil_division(2 * (intervals[0][1] * s_i - 2 * b), n)
                s_i_found = False
                while r < n:
                    s = ceil_division((2 * b + r * n), intervals[0][1])
                    while s * intervals[0][0] < (3 * b + r * n):
                        trial_c = (c_0 * power_mod(s, e, n)) % n
                        if rsa_oracle.oracle(int_to_bytes(trial_c)):
                            s_i = s
                            s_i_found = True
                            break
                        s += 1
                    if s_i_found:
                        break
                    r += 1

        for interval in intervals:
            r, r_max = ceil_division((interval[0] * s_i - 3 * b + 1), n), \
                       floor_division((interval[1] * s_i - 2 * b), n)
            while r * n <= (interval[1] * s_i - 2 * b):
                new_range = (max(interval[0], ceil_division((2 * b + r * n), s_i)),
                             min(interval[1], floor_division((3 * b - 1 + r * n), s_i)))
                union_intervals(new_intervals, new_range)
                r += 1
        i += 1
        intervals = new_intervals

    print("Done!", flush=True)
    return intervals[0][0] % n


KEY_LENGTH = 128
P, Q = generate_small_prime(e=3, length=KEY_LENGTH)
PK, SK = simple_rsa_keygen(P, Q, e=3)


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 47: Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)")

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
