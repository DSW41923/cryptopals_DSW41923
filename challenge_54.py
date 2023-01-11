import argparse
import secrets

from itertools import combinations

from challenge_08 import split_by_length
from challenge_52 import bad_merkle_damgard


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 54: Kelsey and Kohno's Nostradamus Attack")
    print("Printing all byte strings in hex for better look")

    k = 5
    state_length = 2
    block_length = 16
    states = []
    collisions = {}
    for _ in range(2 ** k):
        states.append(secrets.token_bytes(state_length))
    round = 1
    targets = [state for state in states]
    print("Building diamond structure with {} initial hash values".format(len(targets)))
    while len(states) > 1:
        new_states = []
        for state_0, state_1 in zip(states[:-1:2], states[1::2]):
            reverse_hash_table_0 = {}
            reverse_hash_table_1 = {}

            for i in range(2 ** (8 * block_length)):
                i_bytes = i.to_bytes(block_length, 'big')
                hash_value_0 = bad_merkle_damgard(i_bytes, state_0)
                hash_value_1 = bad_merkle_damgard(i_bytes, state_1)
                if hash_value_0 in reverse_hash_table_1:
                    collisions.update({(state_0, i_bytes): hash_value_0})
                    collisions.update({(state_1, reverse_hash_table_1[hash_value_0]): hash_value_0})
                    new_states.append(hash_value_0)
                    break

                if hash_value_1 in reverse_hash_table_0:
                    collisions.update({(state_0, reverse_hash_table_0[hash_value_1]): hash_value_1})
                    collisions.update({(state_1, i_bytes): hash_value_1})
                    new_states.append(hash_value_1)
                    break

                reverse_hash_table_0.update({
                        hash_value_0: i_bytes
                    })
                reverse_hash_table_1.update({
                        hash_value_1: i_bytes
                    })

            print("Round {} hashed {} 1-byte blocks to get one collision".format(round, i))
            round += 1
        states = new_states

    prediction = states[0]
    print("Prediction is {}".format(prediction.hex()))
    msg = secrets.token_bytes(block_length * 3)
    print("Game result is {}".format(msg.hex()))

    result = msg
    initial_state = b''
    for i in range(2 ** (8 * state_length)):
        i_bytes = i.to_bytes(block_length, 'big')
        hash_value = bad_merkle_damgard(msg, i_bytes)
        if hash_value in targets:
            initial_state = i_bytes
            print("Found good initial state {}".format(initial_state.hex()))

    if initial_state == b'':
        initial_state = (0).to_bytes(state_length, 'big')
        print("Manually set initial state as {}".format(initial_state.hex()))

    state = initial_state
    hash_values = []
    for i in range(2 ** (8 * block_length)):
        i_bytes = i.to_bytes(block_length, 'big')
        trial_msg = msg + i_bytes
        hash_value = bad_merkle_damgard(trial_msg, initial_state)
        if hash_value not in hash_values:
            hash_values.append(hash_value)
            if hash_value in targets:
                print("Appending bridge block {}".format(i_bytes.hex()))
                result = trial_msg
                state = hash_value
                print("Next collision state {}\n".format(state.hex()))
                break

    while state != prediction:
        for collision_key, collision_value in collisions.items():
            if collision_key[0] == state:
                print("Appending bridge block {}".format(collision_key[1].hex()))
                result += collision_key[1]
                state = collision_value
                print("Next collision state {}\n".format(state.hex()))

    print("Final result is {}".format(result.hex()))
    print("Is final result hash with state {} equal to prediction? {}".format(initial_state.hex(), bad_merkle_damgard(result, initial_state) == prediction))


if __name__ == "__main__":
    main()
