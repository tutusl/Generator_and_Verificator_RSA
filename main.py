import os
import cryptoUtils
from hashlib import sha512
import base64


def decypher_message(crypto_object, cyphered_text):
    return crypto_object.aes_decrypt(cyphered_text)

def decypher_key(crypto_object, pvt_key):
    return crypto_object.rsa_oaep_decrypt(cyphered_key, pvt_key)


def chyper_key(crypto_object, pub_key):
    return crypto_object.rsa_oaep_encrypt(crypto_object.get_aes_key(), pub_key)


def cypher_message(crypto_object, text_to_cypher):
    return crypto_object.aes_encrypt(text_to_cypher)


def make_signature(cyphered_text, pvt_key):
    hash_calc = int.from_bytes(sha512(cyphered_text).digest(), byteorder='big')
    signature = pow(hash_calc, pvt_key[0], pvt_key[1])
    return signature, hash_calc


def verify_signature(pub_key, digital_signature, original_hash):
    hash_from_signature = pow(digital_signature, pub_key[0], pub_key[1])
    return original_hash == hash_from_signature


if __name__ == "__main__":
    crypto_object = cryptoUtils.CypherAndDecypher(aes_iv=os.urandom(16))
    with open("public_key.txt","r") as f:
        contents = f.readlines()
        pub_key = (int(contents[0]), int(contents[1]))
    with open("private_key.txt","r") as f:
        contents = f.readlines()
        pvt_key = (int(contents[0]), int(contents[1]))
    text_to_cypher = b'oi, eu sou legal'

    import pdb; pdb.set_trace()
    cyphered_text = cypher_message(crypto_object, text_to_cypher)
    cyphered_key = chyper_key(crypto_object, pub_key)
    digital_signature, original_hash = make_signature(cyphered_text, pvt_key)
    crypto_object.aes_key = cyphered_key

    import pdb;
    pdb.set_trace()

    decyphered_key = decypher_key(crypto_object, pvt_key)
    crypto_object.aes_key = decyphered_key
    decyphered_text = decypher_message(crypto_object, cyphered_text)
    verified = verify_signature(pub_key, digital_signature, original_hash)

    import pdb; pdb.set_trace()
    

