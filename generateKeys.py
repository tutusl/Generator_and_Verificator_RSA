import cryptoUtils
from pathlib import Path

key_generator = cryptoUtils.KeyGenerator()
pub_key, pvt_key = key_generator.generate_asymmetric_key()

pub_key_name = Path('public_key.txt')
if not pub_key_name.is_file():
    pub_key_name.touch(exist_ok=True)
    with open("public_key.txt","a") as f:
        f.write(str(pub_key[0]) + '\n' + str(pub_key[1]))

pvt_key_name = Path('private_key.txt')
if not pvt_key_name.is_file():
    pvt_key_name.touch(exist_ok=True)
    with open("private_key.txt","a") as f:
        f.write(str(pvt_key[0]) + '\n' + str(pvt_key[1]))
