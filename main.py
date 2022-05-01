import os
import cryptoUtils
import hashlib
import base64

def make_signature(m, cyphered_text, pvt_key):
    m.update(cyphered_text)
    digital_signature = crypto_object.rsa_oaep_encrypt(m.digest(), pvt_key)
    return base64.b64encode(digital_signature)

def verify_signature(m, pub_key, digital_signature, original_hash):
    cyphered_text = base64.b64decode(digital_signature)
    hash = crypto_object.rsa_oaep_decrypt(cyphered_text , pub_key)
    m.update(hash)

if __name__ == "__main__":
    key_generator = cryptoUtils.KeyGenerator()
    crypto_object = cryptoUtils.CypherAndDecypher(aes_iv=os.urandom(16))
    m = hashlib.sha256()
    pub_key, pvt_key = key_generator.generate_asymmetric_key()
    text_to_cypher = b'oi, eu sou legal'
    cyphered_text = crypto_object.aes_encrypt(text_to_cypher)
    print(pub_key, pvt_key)
    print()
    print(cyphered_text)
    print()
    decyphered_text = crypto_object.aes_decrypt(cyphered_text)
    print(decyphered_text)
    print()
    print(crypto_object.get_aes_key())
    print()
    cyphered_key = crypto_object.rsa_oaep_encrypt(crypto_object.get_aes_key(), pub_key)
    print(cyphered_key)
    print()
    decyphered_key = crypto_object.rsa_oaep_decrypt(cyphered_key, pvt_key)
    print(decyphered_key)
    print()
    original_hash = m.digest()
    digital_signature = make_signature(m, cyphered_text, pvt_key)
    verify_signature(m, pub_key, digital_signature, original_hash)
    import pdb; pdb.set_trace()
    

