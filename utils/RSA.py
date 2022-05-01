from math import ceil
import os
import hashlib

class RsaOaep:
    def encrypt_oaep(self, m, public_key):
        '''Encrypt a byte array with OAEP padding'''
        hlen = 20  # SHA-1 hash length
        k = self.get_key_len(public_key)
        assert len(m) <= k - hlen - 2
        return self.encrypt_raw(self.oaep_encode(m, k), public_key)

    def decrypt_oaep(self, c, private_key):
        '''Decrypt a cipher byte array with OAEP padding'''
        k = self.get_key_len(private_key)
        hlen = 20  # SHA-1 hash length
        assert len(c) == k
        assert k >= 2 * hlen + 2
        return self.oaep_decode(self.decrypt_raw(c, private_key), k)
    
    def oaep_encode(self, m, k, label=b''):
        '''EME-OAEP encoding'''
        mlen = len(m)
        lhash = self.sha1(label)
        hlen = len(lhash)
        ps = b'\x00' * (k - mlen - 2 * hlen - 2)
        db = lhash + ps + b'\x01' + m
        seed = os.urandom(hlen)
        db_mask = self.mgf1(seed, k - hlen - 1)
        masked_db = self.xor(db, db_mask)
        seed_mask = self.mgf1(masked_db, hlen)
        masked_seed = self.xor(seed, seed_mask)
        return b'\x00' + masked_seed + masked_db
    
    def oaep_decode(self, c, k, label=b''):
        '''EME-OAEP decoding'''
        clen = len(c)
        lhash = self.sha1(label)
        hlen = len(lhash)
        _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
        seed_mask = self.mgf1(masked_db, hlen)
        seed = self.xor(masked_seed, seed_mask)
        db_mask = self.mgf1(seed, k - hlen - 1)
        db = self.xor(masked_db, db_mask)
        _lhash = db[:hlen]
        assert lhash == _lhash
        i = hlen
        while i < len(db):
            if db[i] == 0:
                i += 1
                continue
            elif db[i] == 1:
                i += 1
                break
            else:
                raise Exception()
        m = db[i:]
        return m

    def encrypt_raw(self, m, public_key):
        '''Encrypt a byte array without padding'''
        k = self.get_key_len(public_key)
        c = self.encrypt(self.os2ip(m), public_key)
        return self.i2osp(c, k)

    def decrypt_raw(self, c, private_key):
        '''Decrypt a cipher byte array without padding'''
        k = self.get_key_len(private_key)
        m = self.decrypt(self.os2ip(c), private_key)
        return self.i2osp(m, k)

    def mgf1(self, seed, mlen):
        '''MGF1 mask generation function with SHA-1'''
        t = b''
        hlen = len(self.sha1(b''))
        for c in range(0, ceil(mlen / hlen)):
            _c = self.i2osp(c, 4)
            t += self.sha1(seed + _c)
        return t[:mlen]

    @staticmethod
    def get_key_len(key):
        '''Get the number of octets of the public/private key modulus'''
        _, n = key
        return n.bit_length() // 8

    @staticmethod
    def os2ip(x):
        '''Converts an octet string to a nonnegative integer'''
        return int.from_bytes(x, byteorder='big')

    @staticmethod
    def i2osp(x, xlen):
        '''Converts a nonnegative integer to an octet string of a specified length'''
        return x.to_bytes(xlen, byteorder='big')

    @staticmethod
    def sha1(m):
        '''SHA-1 hash function'''
        hasher = hashlib.sha1()
        hasher.update(m)
        return hasher.digest()

    @staticmethod
    def xor(data, mask):
        '''Byte-by-byte XOR of two byte arrays'''
        masked = b''
        ldata = len(data)
        lmask = len(mask)
        for i in range(max(ldata, lmask)):
            if i < ldata and i < lmask:
                masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
            elif i < ldata:
                masked += data[i].to_bytes(1, byteorder='big')
            else:
                break
        return masked

    @staticmethod
    def encrypt(m, public_key):
        '''Encrypt an integer using RSA public key'''
        e, n = public_key
        return pow(m, e, n)

    @staticmethod
    def decrypt(c, private_key):
        '''Decrypt an integer using RSA private key'''
        d, n = private_key
        return pow(c, d, n)
