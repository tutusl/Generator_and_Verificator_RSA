import random
import os
from utils.RabinMiller import MillerTest as MT
from utils.AesEncryption import AES
from utils.RSA import RsaOaep


class KeyGenerator:
    def generate_asymmetric_key(self, key_size=1024):
        print('Generating p prime...')
        p = self.__generate_large_prime(key_size)
        print('Generating q prime...')
        q = self.__generate_large_prime(key_size)
        assert p != q
        n = p * q
        phi = (p - 1) * (q - 1)

        print('Generating e that is relatively prime to (p-1)*(q-1)...')
        while True:
            # generating small e
            e = random.randrange(2, phi-1)
            if self.__gcd(e, phi) == 1:
                break

        print('Calculating d that is mod inverse of e...')
        d = self.__find_mod_inverse(e, phi)

        public_key = (e, n)
        private_key = (d, n)

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

    @staticmethod
    def __generate_large_prime(key_size):
        miller_test = MT()
        while True:
            num = random.randrange(2**(key_size-1), 2**key_size)
            if miller_test.is_prime(num):
                return num

    @staticmethod
    def __gcd(a, b):
        while a != 0:
            a, b = b % a, a
        return b

class CypherAndDecypher:
    def __init__(self, aes_iv):
        self.aes_key = os.urandom(16)
        self.aes_iv = aes_iv
        self.aes = AES(self.aes_key)
        self.rsa = RsaOaep()
    
    def aes_encrypt(self, plain_text):
        return self.aes.encrypt_ctr(plain_text, self.aes_iv)
    
    def aes_decrypt(self, cypher_text):
        return self.aes.decrypt_ctr(cypher_text, self.aes_iv)

    def rsa_oaep_encrypt(self, message, public_key):
        return self.rsa.encrypt_oaep(message, public_key)
    
    def rsa_oaep_decrypt(self, cypher, private_key):
        return self.rsa.decrypt_oaep(cypher, private_key)

    def get_aes_key(self):
        return self.aes_key
