import argparse
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from challenge_08 import split_by_length
from challenge_09 import padding_to_length


H = secrets.token_bytes(2)
F_COUNT = 0


def simple_hash(key: bytes, msg: bytes, result_len: int):
    # Prepare encryptor
    backend = default_backend()

    plaintext_blocks = split_by_length(key, 16)
    for block_num, block in enumerate(plaintext_blocks):
        if len(block) < 16:
            block = padding_to_length(block, 16)

        cipher = Cipher(algorithms.AES(block), modes.ECB(), backend=backend)
        encryptor = cipher.encryptor()
        msg = encryptor.update(msg)
    return msg[:result_len]


def bad_merkle_damgard(msg: bytes, init_state: bytes, result_len: int = None):
    result_len = len(init_state) if not result_len else result_len
    h = padding_to_length(init_state, 16)
    return simple_hash(msg, h, result_len)


def get_collisions(block_length: int, init_state: bytes):
    reverse_hash_table = {}
    for i in range(2 ** 128):
        i_bytes = i.to_bytes(block_length, 'big')
        hash_value = bad_merkle_damgard(i_bytes, init_state)
        if hash_value in reverse_hash_table:
            return reverse_hash_table[hash_value], i_bytes
        reverse_hash_table.update({hash_value: i_bytes})


def f(n):
    global F_COUNT
    # Get n collision pairs
    h = H
    collisions = []
    for _ in range(n):
        F_COUNT += 1
        new_collision = get_collisions(16, h)
        collisions.append(new_collision)
        assert bad_merkle_damgard(new_collision[0], h) == bad_merkle_damgard(new_collision[1], h)
        h = bad_merkle_damgard(new_collision[0], h)

    return collisions


def main():
    global F_COUNT

    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 52: Iterated Hash Function Multicollisions")

    n = 10
    n_collisions = f(n)
    print("Found first {} element collisions".format(n))
    while True:
        reverse_hash_table = {}
        for i in range(2 ** n):
            candidate = b''
            for index, j in enumerate(map(int, list(bin(i)[2:]))):
                candidate += n_collisions[index][j]

            hash_value = bad_merkle_damgard(candidate, H, result_len=3)
            if hash_value in reverse_hash_table:
                print("Found collision of hash value {}:\n{}\n{}".format(hash_value.hex(),
                                                                         reverse_hash_table[hash_value].hex(),
                                                                         candidate.hex()))
                print("Collision function is called {} times".format(F_COUNT))
                return
            reverse_hash_table.update({hash_value: candidate})

        h = H
        for i in range(n):
            h = bad_merkle_damgard(n_collisions[i][0], h)
        F_COUNT += 1
        n_collisions.append(get_collisions(16, h))
        n += 1


if __name__ == "__main__":
    main()
