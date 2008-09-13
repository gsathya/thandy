
# These require PyCrypto.
import Crypto.PublicKey.RSA
import Crypto.Hash.SHA256

import sexp.access
import sexp.encode
import sexp.parse

import binascii
import os

class CryptoError(Exception):
    pass

class PubkeyFormatException(Exception):
    pass

class UnknownMethod(Exception):
    pass

class PublicKey:
    def format(self):
        raise NotImplemented()
    def sign(self, data):
        # returns a list of method,signature tuples.
        raise NotImplemented()
    def checkSignature(self, method, data, signature):
        # returns True, False, or raises UnknownMethod.
        raise NotImplemented()
    def getKeyID(self):
        raise NotImplemented()
    def getRoles(self):
        raise NotImplemented()

def intToBinary(number):
    h = hex(number)
    assert h[:2] == '0x'
    return binascii.a2b_hex(h[2:])

def binaryToInt(binary):
    return int(binascii.b2a_hex(binary), 16)

def _pkcs1_padding(m, size):

    # I'd rather use OAEP+, but apparently PyCrypto barely supports
    # signature verification, and doesn't seem to support signature
    # verification with nondeterministic padding.  "argh."

    s = [ "\x00\x01", "\xff"* (size-3-len(m)), "\x00", m ]
    r = s.join()
    return r

class RSAKey(PublicKey):
    def __init__(self, key):
        self.key = key

    @staticmethod
    def generate(bits=2048):
        key = Crypto.PublicKey.RSA.generate(bits=bits, randfunc=os.urandom)
        return RSAKey(key)

    @staticmethod
    def fromSExpression(sexpr):
        # sexpr must match PUBKEY_SCHEMA
        typeattr = s_child(sexpr[1], "type")[1]
        if typeattr[1] != "rsa":
            return None
        if len(sexpr[2]) != 2:
            raise PubkeyFormatException("RSA keys must have an e,n pair")
        e,n = sexpr[2]
        key = Crypto.PublicKey.RSA.construct((binaryToInt(n), binaryToInt(e)))
        return RSAKey(key)

    def format(self):
        n = intToBinary(self.key.n)
        e = intToBinary(self.key.e)
        return ("pubkey", [("type", "rsa")], (e, n))

    def sign(self, sexpr):
        d_obj = Crypto.Digest.SHA256.new()
        sexpr.encode.hash_canonical(sexpr, d_obj)
        m = _pkcs1_padding(d_obj.digest(), (self.key.size()+1) // 8)
        return ("sha256-pkcs1", self.key.sign(m, "")[0])

    def checkSignature(self, method, sexpr, sig):
        if method != "sha256-pkcs1":
            raise UnknownMethod("method")
        d_obj = Crypto.Digest.SHA256.new()
        sexpr.encode.hash_canonical(sexpr, d_obj)
        m = _pkcs1_padding(d_obj.digest(), (self.key.size()+1) // 8)
        return self.key.verify(sig, m)


