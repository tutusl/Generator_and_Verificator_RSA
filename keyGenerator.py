import millerTest
import random


class KeyGenerator:
    def __init__(self, key_size=1024):
        self.key_size = key_size

    def generate_key(self):
        print('Generating p prime...')
        p = self.__generate_large_prime()
        print('Generating q prime...')
        q = self.__generate_large_prime()
        n = p * q
        phi = (p - 1) * (q - 1)

        print('Generating e that is relatively prime to (p-1)*(q-1)...')
        while True:
            e = random.randrange(2 ** self.key_size, 2 ** (self.key_size+1))
            if self.__gcd(e, phi) == 1:
                break

        print('Calculating d that is mod inverse of e...')
        d = self.__find_mod_inverse(e, phi)

        public_key = (n, e)
        private_key = (n, d)

        return public_key, private_key

    def __find_mod_inverse(self, a, m):
        if self.__gcd(a, m) != 1:
            return None
        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m

        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3

        return u1 % m

    def __generate_large_prime(self):
        miller_test = millerTest.MilerTest(accuracy=40)
        while True:
            num = random.randrange(2**self.key_size, 2**(self.key_size+1))
            if miller_test.is_prime(num):
                return num

    @staticmethod
    def __gcd(a, b):
        while a != 0:
            a, b = b % a, a
        return b
