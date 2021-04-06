import argparse
import random
import secrets

from cryptography.hazmat.primitives.hashes import SHA256
from math import log
from challenge_33 import power_mod
from challenge_36 import simple_sha256, N
from challenge_server import HMAC


# Using top 200 most common passwords of the year 2020 from https://nordpass.com/most-common-passwords-list/
# as password dictionary
PASSWORD_DICTIONARY = ["123456", "123456789", "picture1", "password",
                       "12345678", "111111", "123123", "12345",
                       "1234567890", "senha", "1234567", "qwerty",
                       "abc123", "Million2", "000000", "1234",
                       "iloveyou", "aaron431", "password1", "qqww1122",
                       "123", "omgpop", "123321", "654321", "qwertyuiop",
                       "qwer123456", "123456a", "a123456", "666666",
                       "asdfghjkl", "ashley", "987654321", "unknown",
                       "zxcvbnm", "112233", "chatbooks", "20100728",
                       "123123123", "princess", "jacket025", "evite",
                       "123abc", "123qwe", "sunshine", "121212", "dragon",
                       "1q2w3e4r", "5201314", "159753", "0123456789",
                       "pokemon", "qwerty123", "Bangbang123", "jobandtalent",
                       "monkey", "1qaz2wsx", "abcd1234", "default", "aaaaaa",
                       "soccer", "123654", "ohmnamah23", "12345678910", "zing",
                       "shadow", "102030", "11111111", "asdfgh", "147258369",
                       "qazwsx", "qwe123", "michael", "football", "baseball",
                       "1q2w3e4r5t", "party", "daniel", "asdasd", "222222",
                       "myspace1", "asd123", "555555", "a123456789", "888888",
                       "7777777", "fuckyou", "1234qwer", "superman", "147258",
                       "999999", "159357", "love123", "tigger", "purple",
                       "samantha", "charlie", "babygirl", "88888888", "jordan23",
                       "789456123", "jordan", "anhyeuem", "killer", "basketball",
                       "michelle", "1q2w3e", "lol123", "qwerty1", "789456",
                       "6655321", "nicole", "naruto", "master", "chocolate",
                       "maggie", "computer", "hannah", "jessica", "123456789a",
                       "password123", "hunter", "686584", "iloveyou1", "987654321",
                       "justin", "cookie", "hello", "blink182", "andrew", "25251325",
                       "love", "987654", "bailey", "princess1", "0123456", "101010",
                       "12341234", "a801016", "1111", "1111111", "anthony", "yugioh",
                       "fuckyou1", "amanda", "asdf1234", "trustno1", "butterfly",
                       "x4ivygA51F", "iloveu", "batman", "starwars", "summer",
                       "michael1", "00000000", "lovely", "jakcgt333", "buster",
                       "jennifer", "babygirl1", "family", "456789", "azerty", "andrea",
                       "q1w2e3r4", "qwer1234", "hello123", "10203", "matthew", "pepper",
                       "12345a", "letmein", "joshua", "131313", "123456b", "madison",
                       "Sample123", "777777", "football1", "jesus1", "taylor", "b123456",
                       "whatever", "welcome", "ginger", "flower", "333333", "1111111111",
                       "robert", "samsung", "a12345", "loveme", "gabriel", "alexander",
                       "cheese", "passw0rd", "142536", "peanut", "11223344", "thomas", "angel1"]
I = "challenge_38@cryptopals.com"
# Assume that client's password is one of the most common passwords
# Choose randomly to mimic different careless clients
P = random.choice(PASSWORD_DICTIONARY)


# noinspection PyPep8Naming
def password_cracking(max_bytes, hmac_func, salt, A, b, B, u, C_hmac, **kwargs):
    for p in PASSWORD_DICTIONARY:
        trial_password = ''.join(p).encode()
        trial_x = int.from_bytes(simple_sha256(salt + trial_password), 'big')
        mitm_S = (power_mod(A, b, N) *
                  power_mod(B, u * trial_x, N) % N)
        mitm_K = simple_sha256(mitm_S.to_bytes(max_bytes, 'big'))
        mitm_hmac = hmac_func.hmac_text(mitm_K, salt)
        if mitm_hmac == C_hmac:
            print("Password cracked!")
            print("C's email is {}".format(kwargs['I']))
            print("C's password is {}\n".format(trial_password.decode()))
            return

# noinspection PyPep8Naming
def dictionary_attack_over_simplified_srp(mitm):
    """
    C & S agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
    Variables with capital are programmed as global var
    """

    N_bytes = int(log(N, 256)) + 1
    g, k = 2, 3
    a = int.from_bytes(secrets.token_bytes(2), 'big')
    b = int.from_bytes(secrets.token_bytes(2), 'big')
    hmac_sha256 = HMAC(blockSize=512, mac_func=SHA256)
    mitm_memory = {}

    # Server S doing something
    salt = secrets.token_bytes(16)
    x = int.from_bytes(simple_sha256(salt + P.encode()), 'big')
    v = power_mod(g, x, N)
    memory_S = {'salt': salt, 'v': v}

    # Client C send something to S
    A = power_mod(g, a, N)
    print("C is sending I={}, A={} to S".format(I, A))
    S_received_A = A

    if mitm:
        print("Man in the middle here intercepting!")
        mitm_memory.update({'I': I, 'A': A})

    # S respond, simplified version
    B = power_mod(g, b, N)
    u = int.from_bytes(secrets.token_bytes(16), 'big')
    print("S is sending salt, B={}, u={} to C".format(B, u))
    C_received_salt = memory_S['salt']
    C_received_B, C_received_u = B, u
    if mitm:
        print("Man in the middle here intercepting but give random values to C")
        mitm_memory.update({'salt': secrets.token_bytes(16),
                            'u': int.from_bytes(secrets.token_bytes(16), 'big'),
                            'b': int.from_bytes(secrets.token_bytes(2), 'big'),
                            })
        mitm_memory['B'] = power_mod(g, mitm_memory['b'], N)
        C_received_salt = mitm_memory['salt']
        C_received_B = mitm_memory['B']
        C_received_u = mitm_memory['u']

    # C computing final K and hmac
    x = int.from_bytes(simple_sha256(C_received_salt + P.encode()), 'big')
    C_computed_S = power_mod(C_received_B, a + C_received_u * x, N)
    C_computed_K = simple_sha256(C_computed_S.to_bytes(N_bytes, 'big'))
    C_computed_hmac = hmac_sha256.hmac_text(C_computed_K, C_received_salt)
    print("C computed HMAC-SHA256(K, salt) as {} in hex".format(C_computed_hmac.hex()))

    # C sending hmac result to verify
    print("C send HMAC-SHA256(K, salt) to S")
    if mitm:
        print("Man in the middle here intercepting hmac!")
        mitm_memory.update({'C_hmac': C_computed_hmac})
        print("Cracking C's password")
        password_cracking(max_bytes=N_bytes, hmac_func=hmac_sha256, **mitm_memory)
    else:
        # S computing final K and hmac
        S_computed_S = power_mod(S_received_A * power_mod(v, u, N), b, N)
        S_computed_K = simple_sha256(S_computed_S.to_bytes(N_bytes, 'big'))
        S_computed_hmac = hmac_sha256.hmac_text(S_computed_K, memory_S['salt'])
        print("S computed HMAC-SHA256(K, salt) as {} in hex".format(S_computed_hmac.hex()))
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

    print("Challenge 38: Offline dictionary attack on simplified SRP")
    print("Running simplified version SRP without man in the middle")
    dictionary_attack_over_simplified_srp(mitm=False)
    print("Run again with man in the middle")
    dictionary_attack_over_simplified_srp(mitm=True)


if __name__ == "__main__":
    main()
