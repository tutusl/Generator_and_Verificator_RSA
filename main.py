import keyGenerator
import os

if __name__ == "__main__":
    key_generator = keyGenerator.KeyGenerator()
    public_key, private_key = key_generator.generate_asymmetric_key(key_size=1024)
    print(public_key)
    print(private_key)
    print(os.urandom(16))
