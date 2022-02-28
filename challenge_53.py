import argparse
import secrets

from challenge_08 import split_by_length
from challenge_52 import bad_merkle_damgard


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 53: Kelsey and Schneier's Expandable Messages")
    print("Printing all byte strings in hex for better look")

    k = 4
    M = secrets.token_bytes(16 * (2 ** k))[:-secrets.choice(range(16))]
    h = secrets.token_bytes(2)
    print("Message size : {} bytes".format(len(M)))
    print("Target hash value is {}".format(bad_merkle_damgard(M, h).hex()))

    state = h
    collisions = {}
    for i in range(k-1, -1, -1):
        reverse_hash_table = {}

        for j in range(2 ** 128):
            j_bytes = j.to_bytes(16, 'big')
            hash_value = bad_merkle_damgard(j_bytes, state)
            if hash_value not in reverse_hash_table:
                reverse_hash_table.update({hash_value: j_bytes})

            if len(reverse_hash_table) == 65536:
                print("Round {} hashed {} 1-byte blocks to get all hash value".format(k-i, j))
                break

        intermediate_collision_found = False
        while not intermediate_collision_found:
            blocks_bytes = secrets.token_bytes(16 * (2 ** i))
            intermediate_hash_value = bad_merkle_damgard(blocks_bytes, state)
            for j in range(2 ** 128):
                j_bytes = j.to_bytes(16, 'big')
                hash_value = bad_merkle_damgard(j_bytes, intermediate_hash_value)
                if hash_value in reverse_hash_table:
                    collisions.update({(state, hash_value): (reverse_hash_table[hash_value], blocks_bytes + j_bytes)})
                    state = hash_value
                    intermediate_collision_found = True
                    break

    hash_values = {}
    hash_value = h
    M_blocks = split_by_length(M, 16)
    for i, block in enumerate(M_blocks):
        hash_values.update({hash_value: i})
        hash_value = bad_merkle_damgard(block, hash_value)

    bridge_block = b''
    M_i = -1
    for j in range(2 ** 128):
        j_bytes = j.to_bytes(16, 'big')
        hash_value = bad_merkle_damgard(j_bytes, state)
        if hash_value in hash_values and hash_values[hash_value] >= 5:
            bridge_block = j_bytes
            M_i = hash_values[hash_value]
            break

    print("Found bridge block {} from forged final state {} to intermediate state for message block {}".format(
        bridge_block.hex(), state.hex(), M_i))

    appendix_length_bit = f'{M_i - k - 1:0{k}b}'
    appendix = b''
    appendix_blocks = list(collisions.values())
    for i, b in enumerate(appendix_length_bit):
        appendix += appendix_blocks[i][int(b)]

    forged_message = appendix + bridge_block + b''.join(M_blocks[M_i:])
    print("Forged new message {} with hash value {}".format(
        forged_message.hex(), bad_merkle_damgard(forged_message, h).hex()))
    print("Forged message size : {} bytes".format(len(forged_message)))


if __name__ == "__main__":
    main()
