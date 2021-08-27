import argparse
import secrets

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend
from challenge_10 import cbc_encryptor, cbc_decryptor
from challenge_33 import power_mod

CBC_IV = secrets.token_bytes(16)


def get_cbc_key(backend, key_bytes):
    digest = Hash(SHA1(), backend=backend)
    digest.update(key_bytes)
    return digest.finalize()[:16]


# noinspection PyPep8Naming
def get_mitmbytes(p, g, A, B):
    if g == 1:
        return (1).to_bytes(2, 'big')
    elif g == p:
        return (0).to_bytes(2, 'big')
    elif g == p - 1:
        if A == p - 1 and B == p - 1:
            return (p - 1).to_bytes(2, 'big')
        else:
            return (1).to_bytes(2, 'big')
    else:
        return "Out of Scope of This Challenge"


# noinspection PyPep8Naming
def g_mitm_dh_demo(p, g, a, b, mitm):
    # A sending group parameters
    print("A is sending p={}, g={}.".format(p, g))

    # Man in the middle intercepting!
    if mitm:
        print("M intercepting!")
        print("M relaying messages between A and B.")

    # B respond ACK to A (or to M and M relay this to A)
    print("B is sending ACK to A.")

    # A sending key
    A = power_mod(g, a, p)
    print("A is sending A={} to B.".format(A))
    B_recieved_A = A

    # B sending key
    B = power_mod(g, b, p)
    print("B is sending B={} to A.".format(B))
    A_recieved_B = B

    # A sending encrypted message
    # Use random message to make it simpler to demonstrate
    msg = secrets.token_bytes(16)
    backend = default_backend()
    cbc_key_a = get_cbc_key(backend, power_mod(A_recieved_B, a, p).to_bytes(2, 'big'))
    encrypted_msg = cbc_encryptor(cbc_key_a, msg, CBC_IV)
    print("A is sending message encrypted as: {} (in hex)".format(encrypted_msg.hex()))

    # B can decrypt!
    cbc_key_b = get_cbc_key(backend, power_mod(B_recieved_A, b, p).to_bytes(2, 'big'))
    decrypted_msg = cbc_decryptor(cbc_key_b, encrypted_msg)
    print("B can decrypt the message: {}".format(decrypted_msg))

    if mitm:
        # MITM can decrypt!
        mitm_bytes = get_mitmbytes(p, g, A, B)
        cbc_key_m = get_cbc_key(backend, mitm_bytes)
        decrypted_msg = cbc_decryptor(cbc_key_m, encrypted_msg)
        print("Man in the middle can decrypt the message: {}".format(decrypted_msg))

    # Print for better look
    print("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("a", help="A's secret key for Diffie-Hellman, positive integer only")
    parser.add_argument("b", help="B's secret key for Diffie-Hellman, positive integer only")
    parser.add_argument("--MITM",
                        help="Specify if man in the middle exist(y/n). Yes by default in order to demonstrate attacks",
                        required=False)
    args = parser.parse_args()
    if args:
        print("Challenge 35: Implement DH with negotiated groups, and break with malicious \"g\" parameters")
    p = 37
    if args.a and args.b:
        try:
            a, b = int(args.a), int(args.b)
        except ValueError:
            print("Invalid secret key value!")
            return

        # Breaking dh when g=1
        print("Break DH with g = 1")
        g_mitm_dh_demo(p, 1, a, b, args.MITM != 'n')
        # Breaking dh when g=p
        print("Break DH with g = p")
        g_mitm_dh_demo(p, p, a, b, args.MITM != 'n')
        # Breaking dh when g=p-1
        print("Break DH with g = p - 1")
        g_mitm_dh_demo(p, p - 1, a, b, args.MITM != 'n')


if __name__ == "__main__":
    main()
