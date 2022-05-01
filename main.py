import os
import cryptoUtils
from hashlib import sha512
from generateKeys import generate_keys
import base64


def decypher_message(crypto_object, cyphered_text):
    return crypto_object.aes_decrypt(base64.b64decode(cyphered_text))


def decypher_key(crypto_object, pvt_key):
    return crypto_object.rsa_oaep_decrypt(base64.b64decode(cyphered_key), pvt_key)


def chyper_key(crypto_object, pub_key):
    return base64.b64encode(crypto_object.rsa_oaep_encrypt(crypto_object.get_aes_key(), pub_key))


def cypher_message(crypto_object, text_to_cypher):
    return base64.b64encode(crypto_object.aes_encrypt(text_to_cypher))


def make_signature(cyphered_text, pvt_key):
    hash_calc = int.from_bytes(sha512(cyphered_text).digest(), byteorder='big')
    signature = pow(hash_calc, pvt_key[0], pvt_key[1])
    return base64.b64encode(bytes(str(signature), 'ascii')), hash_calc


def verify_signature(pub_key, digital_signature, original_hash):
    hash_from_signature = pow(int(base64.b64decode(digital_signature).decode('ascii')), pub_key[0], pub_key[1])
    return original_hash == hash_from_signature


if __name__ == "__main__":
    '''Setting up the variables'''
    generate_keys()
    crypto_object = cryptoUtils.CypherAndDecypher(aes_iv=os.urandom(16))
    with open("public_key.txt","r") as f:
        contents = f.readlines()
        pub_key = (int(contents[0]), int(contents[1]))
    with open("private_key.txt","r") as f:
        contents = f.readlines()
        pvt_key = (int(contents[0]), int(contents[1]))
    text_to_cypher = b"It is a long established fact that a reader will be distracted by the readable content of a page when looking at its layout. The point of using Lorem Ipsum is that it has a more-or-less normal distribution of letters, as opposed to using 'Content here, content here', making it look like readable English. Many desktop publishing packages and web page editors now use Lorem Ipsum as their default model text, and a search for 'lorem ipsum' will uncover many web sites still in their infancy. Various versions have evolved over the years, sometimes by accident, sometimes on purpose (injected humour and the like)."

    print()
    print('text to cypher: ' + str(text_to_cypher))
    print()

    '''Cyphering message, key and signature'''

    cyphered_text = cypher_message(crypto_object, text_to_cypher)
    cyphered_key = chyper_key(crypto_object, pub_key)
    digital_signature, original_hash = make_signature(cyphered_text, pvt_key)
    crypto_object.aes_key = cyphered_key

    print('cyphered_key:' + str(cyphered_key))
    print()
    print('cyphered_text: ' + str(cyphered_text))
    print()
    print('digital_signature: ' + str(digital_signature))
    print()

    '''Decyphering message, key and signature'''

    decyphered_key = decypher_key(crypto_object, pvt_key)
    crypto_object.aes_key = decyphered_key
    decyphered_text = decypher_message(crypto_object, cyphered_text)
    verified = verify_signature(pub_key, digital_signature, original_hash)

    print('decyphered_key:' + str(decyphered_key))
    print()
    print('decyphered_text: ' + str(decyphered_text))
    print()

    if verified:
        print('message was verified successfully!')
    else:
        print("message couldn't be verified!")
