import os
import cryptoUtils

if __name__ == "__main__":
    key_generator = cryptoUtils.KeyGenerator()
    crypto_object = cryptoUtils.CypherAndDecypher(aes_iv=os.urandom(16))
    pub_key, pvt_key = key_generator.generate_asymmetric_key()
    text_to_cypher = b'oi, eu sou legal'
    cyphered_text = crypto_object.aes_encrypt(text_to_cypher)
    print(cyphered_text)
    decypher_text = crypto_object.aes_decrypt(cyphered_text)
    print(decypher_text)
    cyphered_key = crypto_object.rsa_oaep_encrypt(crypto_object.get_aes_key(), pub_key)
    print(cyphered_key)
    decyphered_key = crypto_object.rsa_oaep_decrypt(cyphered_key, pvt_key)
    print(decyphered_key)

    #public_key, private_key = key_generator.generate_asymmetric_key(key_size=1024)
    #print(public_key)
    #print(private_key)
    
