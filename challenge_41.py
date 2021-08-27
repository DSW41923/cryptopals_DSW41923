import argparse
import secrets
import time

from challenge_33 import power_mod
from challenge_36 import simple_sha256
from challenge_38 import PASSWORD_DICTIONARY
from challenge_39 import invmod, generate_big_primes, simple_rsa_keygen, simple_rsa_encrypt, simple_rsa_decrypt

P, Q = generate_big_primes(e=3, length=2048)
PK, SK = simple_rsa_keygen(P, Q, 3)
SERVER_MEMORY = []


def server_decrypt(c):
    total_time = 10
    if any([hm == c for hm in [m['hm'] for m in SERVER_MEMORY]]):
        time.sleep(total_time)
        return
    else:
        start_time = time.time()
        pt = simple_rsa_decrypt(SK, c)
        time_elapsed = time.time() - start_time
        time.sleep(total_time - time_elapsed)
        return pt


def main():
    parser = argparse.ArgumentParser()
    parser.parse_args()

    target_pool = []
    for pwd in PASSWORD_DICTIONARY:
        pwd_num = int.from_bytes(pwd.encode(), 'big')
        c = simple_rsa_encrypt(PK, pwd_num)
        SERVER_MEMORY.append({'time': time.time(), 'hm': simple_sha256(c.to_bytes(256, 'big'))})
        target_pool.append({'C': c, 'P': pwd_num})

    max_attack_round = len(PASSWORD_DICTIONARY)
    try:
        attack_round = int(input("How many rounds of attack to demo? At most {}: ".format(max_attack_round)))
        assert 0 <= attack_round <= max_attack_round
    except (ValueError, AssertionError) as e:
        print("Attacking rounds should be a non-negative integer at most {}!".format(max_attack_round))
        raise e

    attacking_targets = []
    while len(attacking_targets) < attack_round:
        target = secrets.choice(target_pool)
        if target not in attacking_targets:
            attacking_targets.append(target)

    success_count = 0
    for target in attacking_targets:
        n = PK[1]
        s = secrets.randbelow(n)
        while s % n <= 1:
            s = secrets.randbelow(n)
        print("Choosed s as {}".format(s))
        s_inv = invmod(s, n)
        print("Computed s^(-1) % N as {}".format(s_inv))
        new_c = (power_mod(s, PK[0], n) * target['C']) % n
        print("Submitting C' as {}".format(new_c))
        new_p = server_decrypt(new_c)
        if new_p:
            print("Got P' from server as {}".format(new_p))
            cracked_p = (new_p * s_inv) % n
            print("Recovered P as {}".format(cracked_p))
            if cracked_p == target['P']:
                print("Attack Success!")
                success_count += 1
            else:
                print("Attack Failed!")
            print()
        else:
            print("C' is in the memory of server!")

    print("Attack {} times".format(attack_round))
    print("Attack success {} times".format(success_count))
    print("Attack fails {} times".format(attack_round - success_count))


if __name__ == "__main__":
    main()
