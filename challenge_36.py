import argparse
import secrets

from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend
from math import log
from challenge_33 import power_mod
from challenge_server import HMAC

# N is a NIST prime
N = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
        'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
        '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
        '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
        '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
        'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
        'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
        'fffffffffffff', 16)
II = "challenge_36@cryptopals.com"
P = secrets.token_bytes(16)


def simple_sha256(text: bytes) -> bytes:
    backend = default_backend()
    digest = Hash(SHA256(), backend=backend)
    digest.update(text)
    return digest.finalize()


# noinspection PyPep8Naming
def secure_remote_password(a, b, g=2, k=3):
    """
    C & S agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    Variables with capital are programmed as global var
    """

    N_bytes = int(log(N, 256)) + 1
    # Server S doing something
    # By description salt should be a random integer, but I generate as random byte so that it can concat to P directly
    memory_S = {}
    salt = secrets.token_bytes(16)
    xH = simple_sha256(salt + P)
    x = int(xH.hex(), 16)
    v = power_mod(g, x, N)
    memory_S.update({'salt': salt, 'v': v})

    # Client C send something to S
    A = power_mod(g, a, N)
    print("C is sending I={}, A={} to S".format(II, A))
    S_received_A = A

    # S respond
    B = (k * memory_S['v'] + power_mod(g, b, N)) % N
    print("S is sending salt={}, B={} to C".format(memory_S['salt'], B))
    C_received_salt = memory_S['salt']
    C_received_B = B

    # Both S and C doing something
    uH = simple_sha256(A.to_bytes(N_bytes, 'big') + B.to_bytes(N_bytes, 'big'))
    u = int(uH.hex(), 16)

    # C computing final K
    xH = simple_sha256(C_received_salt + P)
    x = int(xH.hex(), 16)
    C_computed_S = power_mod(C_received_B - k * power_mod(g, x, N), a + u * x, N)
    hmac_sha256 = HMAC(blockSize=512, mac_func=SHA256)
    C_computed_K = simple_sha256(C_computed_S.to_bytes(N_bytes, 'big'))
    C_computed_hmac = hmac_sha256.hmac_text(C_computed_K, C_received_salt)
    print("C computed K as {} in hex".format(C_computed_K.hex()))
    print("C computed HMAC-SHA256(K, salt) as {} in hex".format(C_computed_hmac.hex()))

    # S computing final K
    S_computed_S = power_mod(S_received_A * power_mod(v, u, N), b, N)
    S_computed_K = simple_sha256(S_computed_S.to_bytes(N_bytes, 'big'))
    S_computed_hmac = hmac_sha256.hmac_text(S_computed_K, memory_S['salt'])
    print("S computed K as {} in hex".format(S_computed_K.hex()))
    print("S computed HMAC-SHA256(K, salt) as {} in hex".format(S_computed_hmac.hex()))

    # C sending hmac result to verify
    print("C send HMAC-SHA256(K, salt)={} to S".format(C_computed_K))

    # S verifying
    if S_computed_hmac == C_computed_hmac:
        print("Verified!")
        print("S send OK to C!")
    else:
        print("Unauthorized!")

    # Print for better look
    print("\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("a", help="C's secret key for Diffie-Hellman, positive integer only")
    parser.add_argument("b", help="S's secret key for Diffie-Hellman, positive integer only")
    args = parser.parse_args()

    print("Challenge 36: Implement Secure Remote Password (SRP)")

    if args.a and args.b:
        try:
            a, b = int(args.a), int(args.b)
        except ValueError:
            print("Invalid secret key value!")
            return
        secure_remote_password(a, b)


if __name__ == "__main__":
    main()
