import argparse


def power_mod(b, e, m):
    x = 1
    while e > 0:
        b, e, x = (
            b * b % m,
            e // 2,
            b * x % m if e % 2 else x
        )
    return x


# noinspection PyPep8Naming
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("a", help="A's secret key for Diffie-Hellman")
    parser.add_argument("b", help="B's secret key for Diffie-Hellman")
    args = parser.parse_args()
    p = 37
    g = 5
    if args:
        print('Challenge 33: Implement Diffie-Hellman')
    if args.a and args.b:
        a, b = int(args.a), int(args.b)
        A, B = (g ** a) % p, (g ** b) % p
        assert (A ** b) % p == (B ** a) % p

        p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
                'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
                '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
                '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
                '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
                'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
                'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
                'fffffffffffff', 16)
        g = 2

        A, B = power_mod(g, a, p), power_mod(g, b, p)
        print("Correctly Implemented? {}".format(power_mod(A, b, p) == power_mod(B, a, p)))


if __name__ == "__main__":
    main()
