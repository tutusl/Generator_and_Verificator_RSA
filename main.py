import keyGenerator

if __name__ == "__main__":
    key_generator = keyGenerator.KeyGenerator(key_size=1024)
    public_key, private_key = key_generator.generate_key()
    print(public_key)
    print(private_key)
