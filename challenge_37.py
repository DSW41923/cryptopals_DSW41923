import argparse
import secrets

from cryptography.hazmat.primitives.hashes import SHA256
from math import log
from challenge_33 import power_mod
from challenge_36 import simple_sha256
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
II = "challenge_37@cryptopals.com"
P = secrets.token_bytes(16)


# noinspection PyPep8Naming
def breaking_srp(A):
    """
    C & S agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    Variables with capital are programmed as global var
    """

    N_bytes = int(log(N, 256)) + 1
    g, k = 2, 3
    b = int(secrets.token_bytes(2).hex(), 16)
    hmac_sha256 = HMAC(blockSize=512, mac_func=SHA256)

    # Server S doing something
    salt = secrets.token_bytes(16)
    xH = simple_sha256(salt + P)
    x = int(xH.hex(), 16)
    v = power_mod(g, x, N)
    memory_S = {'salt': salt, 'v': v}

    # Client C send something to S
    print("C is sending I={}, A={} to S".format(II, A))
    S_received_A = A

    # S respond
    B = (k * memory_S['v'] + power_mod(g, b, N)) % N
    print("S is sending salt, B to C")
    C_received_salt = memory_S['salt']

    # Both S and C doing something
    if A >= N:
        uH = simple_sha256(A.to_bytes(int(log(A, 256)) + 1, 'big') + B.to_bytes(N_bytes, 'big'))
    else:
        uH = simple_sha256(A.to_bytes(N_bytes, 'big') + B.to_bytes(N_bytes, 'big'))
    u = int(uH.hex(), 16)

    # C computing final K for special case
    if A % N == 0:
        C_computed_K = simple_sha256((0).to_bytes(N_bytes, 'big'))
    else:
        print("Out of the scope of this challenge!")
        return
    print("C computed K as {} in hex".format(C_computed_K.hex()))
    C_computed_hmac = hmac_sha256.hmac_text(C_computed_K, C_received_salt)
    print("C computed HMAC-SHA256(K, salt) as {} in hex".format(C_computed_hmac.hex()))

    # S computing final K
    S_computed_S = power_mod(S_received_A * power_mod(v, u, N), b, N)
    print("S computed S as {}".format(S_computed_S))
    S_computed_K = simple_sha256(S_computed_S.to_bytes(N_bytes, 'big'))
    print("S computed K as {} in hex".format(S_computed_K.hex()))
    S_computed_hmac = hmac_sha256.hmac_text(S_computed_K, memory_S['salt'])
    print("S computed HMAC-SHA256(K, salt) as {} in hex".format(S_computed_hmac.hex()))

    # C sending hmac result to verify
    print("C send HMAC-SHA256(K, salt) to S")

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
    parser.parse_args()

    print("Challenge 37: Break SRP with a zero key")
    print("Breaking SRP when client C send A=0")
    breaking_srp(0)
    print("Breaking SRP when client C send A=N")
    breaking_srp(N)
    print("Breaking SRP when client C send A=N^2")
    breaking_srp(N ** 2)


if __name__ == "__main__":
    main()
