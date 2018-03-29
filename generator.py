from random import randrange


class RSAKeyPairGenerator:
    """
    Generates RSA Key Pairs from random numbers

    References wikipedia: https://en.wikipedia.org/wiki/RSA_(cryptosystem)
    """
    def __init__(self):
        self.p = None
        self.q = None
        self.n = None
        self.e = 2 ** 16 + 1
        self.d = None
        self.public = None
        self.private = None

        # List of first 10000 primes https://primes.utm.edu/lists/small/10000.txt
        with open("10000.txt") as f:
            primes_lst = f.readlines()
            primes_lst = [row.split() for row in primes_lst]
        self.small_primes = [int(prime) for row in primes_lst for prime in row]

    def generate_keys(self):
        check = True
        while check:
            self.p = self.get_prime_number()
            self.q = self.get_prime_number()
            if self.p % self.e != 1 and self.q % self.e != 1 and self.p != self.q:
                check = False
        self.n = self.p * self.q
        phi_n =  (self.p - 1) * (self.q - 1)
        self.d = self.xgcd(self.e, phi_n)
        check = True
        while check:
            if self.d < 0:
                self.d += phi_n
            else:
                check = False
        self.public = (self.e, self.n)
        self.private = (self.d, self.n)
        return self.public, self.private

    def is_prime(self, guess_number):
        for prime in self.small_primes:
            if guess_number % prime == 0:
                return False

        return self.rabin_miller_test(guess_number)

    def rabin_miller_test(self, number, iter_num=10):
        num1 = number - 1
        num2 = 0
        while num1 % 2 == 0:
            num1 //= 2
            num2 += 1

        for i in range(iter_num):
            random_num = randrange(2, number - 1)
            remainder = pow(random_num, num1, number)
            if remainder != 1:
                i = 0
                while remainder != (number - 1):
                    if i == num2 - 1:
                        return False
                    else:
                        i += 1
                        remainder = (remainder ** 2) % number
        return True

    def xgcd(self, number, mod):
        x0, x1, y0, y1 = 1, 0, 0, 1
        while mod != 0:
            q, number, mod = number // mod, mod, number % mod
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return number

    def get_prime_number(self, bitsize=1024):
        while 1:
            number = randrange(2 ** (bitsize - 1), 2 ** bitsize)
            if self.is_prime(number):
                return number
