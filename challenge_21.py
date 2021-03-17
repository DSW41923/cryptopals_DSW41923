import sys
import getopt
import secrets
import time


class MT19937RNG(object):
    """Implementing MT19937 Mersenne Twister RNG"""
    # Parameters of MT19937
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    f = 1812433253
    l = 18
    def __init__(self, seed):
        super(MT19937RNG, self).__init__()
        self.state = []
        self.count = 0
        self.seed_mt(seed)
        
    def seed_mt(self, seed):
        self.count = self.n
        self.state.append(seed)
        for i in range(1, self.n):
            new_state = self.f * (self.state[i-1] ^ (self.state[i-1] >> (self.w-2))) + i
            state_bit = bin(new_state)[2:].zfill(self.w)
            self.state.append(int(state_bit[-self.w:], 2))

    def extract_number(self):
        if not self.state:
            raise

        if self.count == self.n:
            self.twist()

        y = self.state[self.count]
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.count += 1
        return bin(y)[2:].zfill(self.w)[-self.w:]

    # Generate the next n values from the series x_i 
    def twist(self):
        for i in range(self.n):
            current_state_bit = bin(self.state[i])[2:].zfill(self.w)
            next_state_bit = bin(self.state[(i + 1) % self.n])[2:].zfill(self.w)
            x = int(current_state_bit[:(self.w - self.r)] + next_state_bit[-self.r:], 2)
            x_a = x >> 1
            if (x % 2) != 0:
                 x_a = x_a ^ self.a
            self.state[i] = self.state[(i + self.m) % self.n] ^ x_a

        self.count = 0


def main(argv):

    try:
        opts, args = getopt.getopt(argv,"h:",["help"])
    except getopt.GetoptError:
        print('Usage: python3 challenge_21.py [-h | --help]')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', "--help"):
            print('Usage: python3 challenge_21.py [-h | --help]')
            print('Challenge 21: Implement the MT19937 Mersenne Twister RNG')
            sys.exit()

    # Trying the MT19937 RNG
    seed = secrets.choice(range(2 ** 32 - 1))
    first_rng = MT19937RNG(seed)
    outputs = []
    for x in range(64):
        number = first_rng.extract_number()
        outputs.append(number)

    time.sleep(13)

    new_seed = seed
    second_rng = MT19937RNG(new_seed)
    for x in range(64):
        new_number = second_rng.extract_number()
        if outputs[x] != new_number:
            print(seed, new_seed)
            print(outputs[x], new_number)
            print(x)
            print("Incorrect implementation!")
            sys.exit(2)
    print("Correct implementation! Good Job!")


if __name__ == "__main__":
    main(sys.argv[1:])
