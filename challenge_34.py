import argparse
import secrets

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.backends import default_backend
from challenge_10 import cbc_encryptor, cbc_decryptor
from challenge_33 import power_mod


CBC_IV = secrets.token_bytes(16)


# noinspection PyPep8Naming
def DH_demo(p, g, a, b, mitm=False):

    # A sending keys
    A = power_mod(g, a, p)
    print("A is sending p={}, g={}, and A={} to B.".format(p, g, A))
    B_recieved_A = A

    # Man in the middle intercepting!
    if mitm:
        print("M intercept and send p={}, g={}, and A={} to B.".format(p, g, p))
        B_recieved_A = p

    # B sending key
    B = power_mod(g, b, p)
    print("B is sending B={} to A.".format(B))
    A_recieved_B = B

    # Man in the middle intercepting!
    if mitm:
        print("M intercept and send B={} to A.".format(p))
        A_recieved_B = p

    # A sending encrypted message.
    msg = input("Input message to send: ")
    backend = default_backend()
    digest_a = Hash(SHA1(), backend=backend)
    digest_a.update(power_mod(A_recieved_B, a, p).to_bytes(2, 'big'))
    cbc_key_a = digest_a.finalize()[:16]
    encrypted_msg = cbc_encryptor(cbc_key_a, msg.encode(), CBC_IV)
    print("A is sending message encrypted as: {} (in hex)".format(encrypted_msg.hex()))

    if mitm:
        # MITM can decrypt!
        digest_m = Hash(SHA1(), backend=backend)
        digest_m.update(bytes([0, 0]))
        cbc_key_m = digest_m.finalize()[:16]
        decrypted_msg = cbc_decryptor(cbc_key_m, encrypted_msg)
        print("Man in the middle can decrypt the message: {}".format(decrypted_msg))

    digest_b = Hash(SHA1(), backend=backend)
    digest_b.update(power_mod(B_recieved_A, b, p).to_bytes(2, 'big'))
    cbc_key_b = digest_b.finalize()[:16]
    decrypted_msg = cbc_decryptor(cbc_key_b, encrypted_msg)
    print("B can decrypt the message: {}".format(decrypted_msg))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("a", help="A's secret key for Diffie-Hellman, positive integer only")
    parser.add_argument("b", help="B's secret key for Diffie-Hellman, positive integer only")
    parser.add_argument("--MITM",
                        help="Specify if man in the middle exist(y/n). No by default.",
                        required=False)
    args = parser.parse_args()
    if args:
        print('Challenge 34: Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection')
    p = 37
    g = 5
    if args.a and args.b:
        try:
            a, b = int(args.a), int(args.b)
        except ValueError:
            print("Invalid secret key value!")
            return
        DH_demo(p, g, a, b, args.MITM == 'y')


if __name__ == "__main__":
    main()
