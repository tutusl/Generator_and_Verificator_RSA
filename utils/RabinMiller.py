import random


class MillerTest:
    def __init__(self, accuracy=40):
        self.k = accuracy

    def is_prime(self, n):
        # border cases
        if n == 1 or n == 4:
            return False
        if n == 2 or n == 3:
            return True

        d = n - 1
        while d % 2 == 0:
            d //= 2
        for i in range(self.k):
            if not self.__miller_test(d, n):
                return False
        return True

    def __miller_test(self, d, n):
        a = 2 + random.randint(1, n - 4)
        x = self.__mod_power(a, d, n)
        if x == 1 or x == n - 1:
            return True
        while d != n - 1:
            x = (x * x) % n
            d *= 2
            if x == 1:
                return False
            if x == n - 1:
                return True
        return False

    @staticmethod
    def __mod_power(x, y, p):
        res = 1
        x = x % p

        while y > 0:
            if y & 1:
                res = (res * x) % p
            y = y >> 1  # y = y/2
            x = (x * x) % p

        return res
