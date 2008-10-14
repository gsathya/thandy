# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

# These require PyCrypto.
import Crypto.PublicKey.RSA
import Crypto.Hash.SHA256
import Crypto.Cipher.AES

import cPickle as pickle
import binascii
import logging
import os
import struct
import sys
import simplejson
import getpass

import thandy.formats
import thandy.util

class PublicKey:
    """Abstract base class for public keys."""
    def __init__(self):
        self._roles = []
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
        """Remove a list of all roles supported by this key.  A role is
           from this key.  A role is a doctype,pathPattern tuple.
        """
        return self._roles
    def addRole(self, role, path):
        """Add a role to the list of roles supported by this key.
           A role is a permission to sign a given kind of document
           (one of thandy.format.ALL_ROLES) at a given set of relative
           paths.
        """
        assert role in thandy.formats.ALL_ROLES
        self._roles.append((role, path))
    def clearRoles(self):
        """Remove all roles from this key."""
        del self._roles[:]
    def hasRole(self, role, path):
        """Return true iff this key has a role that allows it to sign
           a document of type 'role' at location in the repository 'path'.
        """
        for r, p in self._roles:
            if r == role and thandy.formats.rolePathMatches(p, path):
                return True
        return False

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
        "Variant for future versions of pythons that don't append 'L'."
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

def intToBase64(number):
    """Convert an int or long to a big-endian base64-encoded value."""
    return thandy.formats.formatBase64(intToBinary(number))

def base64ToInt(number):
    """Convert a big-endian base64-encoded value to a long."""
    return binaryToInt(thandy.formats.parseBase64(number))

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
    >>> obj = k.format()
    >>> obj['_keytype']
    'rsa'
    >>> base64ToInt(obj['e'])
    65537L
    >>> k1 = RSAKey.fromJSon(obj)
    >>> k1.key.e == k.key.e
    True
    >>> k1.key.n == k.key.n
    True
    >>> k.getKeyID() == k1.getKeyID()
    True
    >>> s = { 'A B C' : "D", "E" : [ "F", "g", 99] }
    >>> method, sig = k.sign(obj=s)
    >>> k.checkSignature(method, sig, obj=s)
    True
    >>> s2 = [ s ]
    >>> k.checkSignature(method, sig, obj=s2)
    False
    """
    def __init__(self, key):
        PublicKey.__init__(self)
        self.key = key
        self.keyid = None

    @staticmethod
    def generate(bits=2048):
        """Generate a new RSA key, with modulus length 'bits'."""
        key = Crypto.PublicKey.RSA.generate(bits=bits, randfunc=os.urandom)
        return RSAKey(key)

    @staticmethod
    def fromJSon(obj):
        """Construct an RSA key from the output of the format() method.
        """
        # obj must match RSAKEY_SCHEMA

        thandy.formats.RSAKEY_SCHEMA.checkMatch(obj)
        n = base64ToInt(obj['n'])
        e = base64ToInt(obj['e'])
        if obj.has_key('d'):
            d = base64ToInt(obj['d'])
            p = base64ToInt(obj['p'])
            q = base64ToInt(obj['q'])
            u = base64ToInt(obj['u'])
            key = Crypto.PublicKey.RSA.construct((n, e, d, p, q, u))
        else:
            key = Crypto.PublicKey.RSA.construct((n, e))

        result = RSAKey(key)
        if obj.has_key('roles'):
            for r, p in obj['roles']:
                result.addRole(r,p)

        return result

    def isPrivateKey(self):
        """Return true iff this key has private-key components"""
        return hasattr(self.key, 'd')

    def format(self, private=False, includeRoles=False):
        """Returna a new object to represent this key in json format.
           If 'private', include private-key data.  If 'includeRoles',
           include role information.
        """
        n = intToBase64(self.key.n)
        e = intToBase64(self.key.e)
        result = { '_keytype' : 'rsa',
                   'e' : e,
                   'n' : n }
        if private:
            result['d'] = intToBase64(self.key.d)
            result['p'] = intToBase64(self.key.p)
            result['q'] = intToBase64(self.key.q)
            result['u'] = intToBase64(self.key.u)
        if includeRoles:
            result['roles'] = self.getRoles()
        return result

    def getKeyID(self):
        """Return the KeyID for this key.
        """
        if self.keyid == None:
            d_obj = Crypto.Hash.SHA256.new()
            thandy.formats.getDigest(self.format(), d_obj)
            self.keyid = thandy.formats.formatHash(d_obj.digest())
        return self.keyid

    def sign(self, obj=None, digest=None):
        assert _xor(obj == None, digest == None)
        method = "sha256-pkcs1"
        if digest == None:
            digest = thandy.formats.getDigest(obj)
        m = _pkcs1_padding(digest, (self.key.size()+1) // 8)
        sig = intToBase64(self.key.sign(m, "")[0])
        return (method, sig)

    def checkSignature(self, method, sig, obj=None, digest=None):
        assert _xor(obj == None, digest == None)
        if method != "sha256-pkcs1":
            raise UnknownMethod(method)
        if digest == None:
            digest = thandy.formats.getDigest(obj)
        sig = base64ToInt(sig)
        m = _pkcs1_padding(digest, (self.key.size()+1) // 8)
        return bool(self.key.verify(m, (sig,)))

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
    encrypted = e.encrypt("%s%s%s%s" % (slen, secret, d, pad))
    if padlen:
        encrypted = encrypted[:-padlen]
    return "GKEY1%s%s%s"%(salt, iv, encrypted)

def decryptSecret(encrypted, password):
    """Decrypt a value encrypted with encryptSecret.  Raises UnknownFormat
       or FormatError if 'encrypted' was not generated with encryptSecret.
       Raises BadPassword if the password was not correct.
    """
    if encrypted[:5] != "GKEY1":
        raise thandy.UnknownFormat()
    encrypted = encrypted[5:]
    if len(encrypted) < SALTLEN+1+16:
        raise thandy.FormatException()

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
        raise thandy.BadPassword()

    return secret

class KeyStore(thandy.formats.KeyDB):
    """Helper to store private keys in an encrypted file."""
    def __init__(self, fname, encrypted=True):
        thandy.formats.KeyDB.__init__(self)

        self._loaded = None
        self._fname = fname
        self._passwd = None
        self._encrypted = encrypted

    def getpass(self, reprompt=False):
        if self._passwd != None:
            return self._passwd
        while 1:
            pwd = getpass.getpass("Password: ", sys.stderr)
            if not reprompt:
                return pwd

            pwd2 = getpass.getpass("Confirm: ", sys.stderr)
            if pwd == pwd2:
                return pwd
            else:
                print "Mismatch; try again."

    def load(self, password=None):
        logging.info("Loading private keys from %r...", self._fname)
        if not os.path.exists(self._fname):
            logging.info("...no such file.")
            self._loaded = True
            return

        if password is None and self._encrypted:
            password = self.getpass()

        contents = open(self._fname, 'rb').read()
        if self._encrypted:
            contents = decryptSecret(contents, password)

        listOfKeys = simplejson.loads(contents)
        self._passwd = password # It worked.
        if not listOfKeys.has_key('keys'):
            listOfKeys['keys'] = []
        for obj in listOfKeys['keys']:
            key = RSAKey.fromJSon(obj)
            self.addKey(key)
            logging.info("Loaded key %s", key.getKeyID())

        self._loaded = True

    def setPassword(self, passwd):
        self._passwd = passwd

    def clearPassword(self):
        self._passwd = None

    def save(self, password=None):
        if not self._loaded and self._encrypted:
            self.load(password)

        if password is None:
            password = self.getpass(True)

        logging.info("Saving private keys into %r...", self._fname)
        listOfKeys = { 'keys' :
                       [ key.format(private=True, includeRoles=True) for key in
                         self._keys.values() ]
                       }
        contents = simplejson.dumps(listOfKeys)
        if self._encrypted:
            contents = encryptSecret(contents, password)
        thandy.util.replaceFile(self._fname, contents)
        self._passwd = password # It worked.
        logging.info("Done.")


