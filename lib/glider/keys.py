
# These require PyCrypto.
import Crypto.PublicKey.RSA
import Crypto.Hash.SHA256
import Crypto.Cipher.AES

import sexp.access
import sexp.encode
import sexp.parse

import cPickle as pickle
import binascii
import os
import struct

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

    def _digest(self, sexpr, method=None):
        if method in (None, "sha256-pkcs1"):
            d_obj = Crypto.Hash.SHA256.new()
            sexp.encode.hash_canonical(sexpr, d_obj)
            digest = d_obj.digest()
            return ("sha256-pkcs1", digest)

        raise UnknownMethod(method)

    def sign(self, sexpr=None, digest=None):
        assert _xor(sexpr == None, digest == None)
        if digest == None:
            method, digest = self._digest(sexpr)
        m = _pkcs1_padding(digest, (self.key.size()+1) // 8)
        sig = intToBinary(self.key.sign(m, "")[0])
        return (method, sig)

    def checkSignature(self, method, sig, sexpr=None, digest=None):
        assert _xor(sexpr == None, digest == None)
        if method != "sha256-pkcs1":
            raise UnknownMethod("method")
        if digest == None:
            method, digest = self._digest(sexpr, method)
        sig = binaryToInt(sig)
        m = _pkcs1_padding(digest, (self.key.size()+1) // 8)
        return self.key.verify(m, (sig,))

SALTLEN=16

def secretToKey(salt, secret):
    """Convert 'secret' to a 32-byte key, using a version of the algorithm
       from RFC2440.  The salt must be SALTLEN+1 bytes long, and should
       be random, except for the last byte, which encodes how time-
       consuming the computation should be.

       (The goal is to make offline password-guessing attacks harder by
       increasing the time required to convert a password to a key, and to
       make precomputed password tables impossible to generate by )
    """
    assert len(salt) == SALTLEN+1

    # The algorithm is basically, 'call the last byte of the salt the
    # "difficulty", and all other bytes of the salt S.  Now make
    # an infinite stream of S|secret|S|secret|..., and hash the
    # first N bytes of that, where N is determined by the difficulty.
    #
    # Obviously, this wants a hash algorithm that's tricky to
    # parallelize.
    #
    # Unlike RFC2440, we use a 16-byte salt.  Because CPU times
    # have improved, we start at 16 times the previous minimum.

    difficulty = ord(salt[-1])
    count = (16L+(difficulty & 15)) << ((difficulty >> 4) + 10)

    # Make 'data' nice and long, so that we don't need to call update()
    # a zillion times.
    data = salt[:-1]+secret
    if len(data)<1024:
        data *= (1024 // len(data))+1

    d = Crypto.Hash.SHA256.new()
    iters, leftover = divmod(count, len(data))
    for _ in xrange(iters):
        d.update(data)
        #count -= len(data)
    if leftover:
        d.update(data[:leftover])
        #count -= leftover
    #assert count == 0

    return d.digest()

def encryptSecret(secret, password, difficulty=0x80):
    """Encrypt the secret 'secret' using the password 'password',
       and return the encrypted result."""
    # The encrypted format is:
    #    "GKEY1"  -- 5 octets, fixed, denotes data format.
    #    SALT     -- 17 bytes, used to hash password
    #    IV       -- 16 bytes; salt for encryption
    #    ENCRYPTED IN AES256-OFB, using a key=s2k(password, salt) and IV=IV:
    #       SLEN   -- 4 bytes; length of secret, big-endian.
    #       SECRET -- len(secret) bytes
    #       D      -- 32 bytes; SHA256 hash of (salt|secret|salt).
    #
    # This format leaks the secret length, obviously.
    assert 0 <= difficulty < 256
    salt = os.urandom(SALTLEN)+chr(difficulty)
    key = secretToKey(salt, password)

    d_obj = Crypto.Hash.SHA256.new()
    d_obj.update(salt)
    d_obj.update(secret)
    d_obj.update(salt)
    d = d_obj.digest()

    iv = os.urandom(16)
    e = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OFB, iv)

    # Stupidly, pycrypto doesn't accept that stream ciphers don't need to
    # take their input in blocks.  So pad it, then ignore the padded output.

    padlen = 16-((len(secret)+len(d)+4) % 16)
    if padlen == 16: padlen = 0
    pad = '\x00' * padlen

    slen = struct.pack("!L",len(secret))
    encrypted = e.encrypt("%s%s%s%s" % (slen, secret, d, pad))[:-padlen]
    return "GKEY1%s%s%s"%(salt, iv, encrypted)

def decryptSecret(encrypted, password):
    if encrypted[:5] != "GKEY1":
        raise UnknownFormat()
    encrypted = encrypted[5:]
    if len(encrypted) < SALTLEN+1+16:
        raise FormatError()

    salt = encrypted[:SALTLEN+1]
    iv = encrypted[SALTLEN+1:SALTLEN+1+16]
    encrypted = encrypted[SALTLEN+1+16:]

    key = secretToKey(salt, password)

    e = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_OFB, iv)
    padlen = 16-(len(encrypted) % 16)
    if padlen == 16: padlen = 0
    pad = '\x00' * padlen

    decrypted = e.decrypt("%s%s"%(encrypted,pad))
    slen = struct.unpack("!L", decrypted[:4])[0]
    secret = decrypted[4:4+slen]
    hash = decrypted[4+slen:4+slen+Crypto.Hash.SHA256.digest_size]

    d = Crypto.Hash.SHA256.new()
    d.update(salt)
    d.update(secret)
    d.update(salt)

    if d.digest() != hash:
        print repr(decrypted)
        raise BadPassword()

    return secret

