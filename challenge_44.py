import argparse
import random
import re


from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend
from challenge_39 import invmod
from challenge_43 import Q

Y = int("2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
        "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
        "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
        "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
        "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
        "2971c3de5084cce04a2e147821", 16)


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()
    print("Challenge 44: DSA nonce recovery from repeated nonce")

    # Prepare ciphertext to break
    dsa_signed_messages = []
    file_input = open('input_44.txt', 'r')
    msg_inputs = file_input.read()
    for msg, s, r, m in re.findall(r'msg: ([\w \',.]+)\ns: (\d+)\nr: (\d+)\nm: ([abcdef\d]+)', msg_inputs):
        dsa_signed_messages.append({
            'msg': (msg + ' ').encode(),
            's': int(s),
            'r': int(r),
            'm': m,
            'm_num': int(m, 16)
        })
    file_input.close()

    msg1, msg2 = None, None
    while not msg2:
        msg1 = random.choice(dsa_signed_messages)
        for message in dsa_signed_messages:
            if message != msg1 and message['r'] == msg1['r']:
                msg2 = message
                break

    k = (msg1['m_num'] - msg2['m_num']) * invmod((msg1['s'] - msg2['s']) % Q, Q) % Q
    x = (msg1['s'] * k - msg1['m_num']) * invmod(msg1['r'], Q) % Q
    backend = default_backend()
    digest = Hash(SHA1(), backend=backend)
    digest.update(hex(x)[2:].encode())
    result = digest.finalize().hex()
    print("Found private key x = {}".format(x))
    print("Is the digest of the private key correct? {}".format(
        result == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'))


if __name__ == "__main__":
    main()
