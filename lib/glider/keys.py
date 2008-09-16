
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

if hex(1L).upper() == "0X1L":
    def intToBinary(number):
        """Convert an int or long into a big-endian series of bytes.
        """
        # This "convert-to-hex, then use binascii" approach may look silly,
        # but it's over 10x faster than the Crypto.Util.number approach.
        h = hex(long(number))
        h = h[2:-1]
        if len(h)%2:
            h = "0"+h
        return binascii.a2b_hex(h)
elif hex(1L).upper() == "0X1":
    def intToBinary(number):
        h = hex(long(number))
        h = h[2:]
        if len(h)%2:
            h = "0"+h
        return binascii.a2b_hex(h)
else:
    import Crypto.Util.number
    intToBinary = Crypto.Util.number.long_to_bytes
    assert None

def binaryToInt(binary):
   """Convert a big-endian series of bytes into a long.
   """
   return long(binascii.b2a_hex(binary), 16)

def _pkcs1_padding(m, size):

    # I'd rather use OAEP+, but apparently PyCrypto barely supports
    # signature verification, and doesn't seem to support signature
    # verification with nondeterministic padding.  "argh."

    s = [ "\x00\x01", "\xff"* (size-3-len(m)), "\x00", m ]
    r = "".join(s)
    return r

def _xor(a,b):
    if a:
        return not b
    else:
        return b

class RSAKey(PublicKey):
    """
    >>> k = RSAKey.generate(bits=512)
    >>> sexpr = k.format()
    >>> sexpr[:2]
    ('pubkey', [('type', 'rsa')])
    >>> k1 = RSAKey.fromSExpression(sexpr)
    >>> k1.key.e == k.key.e
    True
    >>> k1.key.n == k.key.n
    True
    >>> k.getKeyID() == k1.getKeyID()
    True
    >>> s = ['tag1', ['foobar'], [['foop', 'bar']], 'baz']
    >>> method, sig = k.sign(sexpr=s)
    >>> k.checkSignature(method, sig, sexpr=s)
    True
    >>> s2 = [ s ]
    >>> k.checkSignature(method, sig, sexpr=s2)
    False
    """
    def __init__(self, key):
        self.key = key
        self.keyid = None

    @staticmethod
    def generate(bits=2048):
        key = Crypto.PublicKey.RSA.generate(bits=bits, randfunc=os.urandom)
        return RSAKey(key)

    @staticmethod
    def fromSExpression(sexpr):
        # sexpr must match PUBKEY_SCHEMA
        typeattr = sexp.access.s_attr(sexpr[1], "type")
        if typeattr != "rsa":
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

    def getKeyID(self):
        if self.keyid == None:
            n = intToBinary(self.key.n)
            e = intToBinary(self.key.e)
            keyval = (e,n)
            d_obj = Crypto.Hash.SHA256.new()
            sexp.encode.hash_canonical(keyval, d_obj)
            self.keyid = ("rsa", d_obj.digest())
        return self.keyid

    def sign(self, sexpr=None, digest=None):
        assert _xor(sexpr == None, digest == None)
        if digest == None:
            d_obj = Crypto.Hash.SHA256.new()
            sexp.encode.hash_canonical(sexpr, d_obj)
            digest = d_obj.digest()
        m = _pkcs1_padding(digest, (self.key.size()+1) // 8)
        sig = intToBinary(self.key.sign(m, "")[0])
        return ("sha256-pkcs1", sig)

    def checkSignature(self, method, sig, sexpr=None, digest=None):
        assert _xor(sexpr == None, digest == None)
        if method != "sha256-pkcs1":
            raise UnknownMethod("method")
        if digest == None:
            d_obj = Crypto.Hash.SHA256.new()
            sexp.encode.hash_canonical(sexpr, d_obj)
            digest = d_obj.digest()
        sig = binaryToInt(sig)
        m = _pkcs1_padding(digest, (self.key.size()+1) // 8)
        return self.key.verify(m, (sig,))


