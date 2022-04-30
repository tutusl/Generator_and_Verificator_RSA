import os
import cryptoUtils

if __name__ == "__main__":
    key_generator = cryptoUtils.KeyGenerator()
    crypto_object = cryptoUtils.CypherAndDecypher(aes_iv=os.urandom(16))
    text_to_cypher = b'oi, eu sou legal'
    cypher_text = crypto_object.aes_encrypt(text_to_cypher)
    print(cypher_text)
    decypher_text = crypto_object.aes_decrypt(cypher_text)
    print(decypher_text)
    #public_key, private_key = key_generator.generate_asymmetric_key(key_size=1024)
    #print(public_key)
    #print(private_key)
    
