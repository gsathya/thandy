# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import time
import re
import binascii
import calendar
import os

import thandy.checkJson
import thandy.util

json = thandy.util.importJSON()

import Crypto.Hash.SHA256

class KeyDB:
    """A KeyDB holds public keys, indexed by their key IDs."""
    ## Fields:
    #   _keys: a map from keyid to public key.
    def __init__(self):
        """Create a new empty KeyDB."""
        self._keys = {}
    def addKey(self, k):
        """Insert a thandy.keys.PublicKey object, 'k', into this KeyDB.  If
           we already had this key, retain the old one, but add any roles in
           the new key 'k'.
        """
        keyid = k.getKeyID()
        try:
            oldkey = self._keys[keyid]
            for r, p in oldkey.getRoles():
                if (r, p) not in k.getRoles():
                    k.addRole(r,p)
        except KeyError:
            pass
        self._keys[k.getKeyID()] = k
    def getKey(self, keyid):
        """Return the key whose key ID is 'keyid'.  If there is no such key,
           raise KeyError."""
        return self._keys[keyid]
    def getKeysByRole(self, role, path):
        """Return a list of all keys that have the role 'role' set for files
           in 'path'."""
        results = []
        for key in self._keys.itervalues():
            for r,p in key.getRoles():
                if r == role:
                    if rolePathMatches(p, path):
                        results.append(key)
        return results

    def getKeysFuzzy(self, keyid):
        """Return a list of all keys whose key IDs begin with 'keyid'."""
        r = []
        for k,v in self._keys.iteritems():
            if k.startswith(keyid):
                r.append(v)
        return r
    def iterkeys(self):
        """Return a new iterator of all the keys in this KeyDB."""
        return self._keys.itervalues()

# Internal cache that maps role paths to regex objects that parse them.
_rolePathCache = {}
def rolePathMatches(rolePath, path):
    """Return true iff the relative path in the filesystem 'path' conforms
       to the pattern 'rolePath': a path that a given key is
       authorized to sign.  Patterns are allowed to contain * to
       represent one or more characters in a filename, and ** to
       represent any level of directory structure.

    >>> rolePathMatches("a/b/c/", "a/b/c/")
    True
    >>> rolePathMatches("**/c.*", "a/b/c.txt")
    True
    >>> rolePathMatches("**/c.*", "a/b/ctxt")
    False
    >>> rolePathMatches("**/c.*", "a/b/c.txt/foo")
    False
    >>> rolePathMatches("a/*/c", "a/b/c")
    True
    >>> rolePathMatches("a/*/c", "a/b/c.txt")
    False
    >>> rolePathMatches("a/*/c", "a/b/c.txt") #Check cache
    False
    """
    try:
        regex = _rolePathCache[rolePath]
    except KeyError:
        orig = rolePath
        # remove duplicate slashes.
        rolePath = re.sub(r'/+', '/', rolePath)
        # escape, then ** becomes .*
        rolePath = re.escape(rolePath).replace(r'\*\*', r'.*')
        # * becomes [^/]*
        rolePath = rolePath.replace(r'\*', r'[^/]*')
        # and no extra text is allowed.
        rolePath += "$"
        regex = _rolePathCache[orig] = re.compile(rolePath)
    return regex.match(path) != None

class SignatureStatus:
    """Represents the outcome of checking signature(s) on an object."""
    def __init__(self, good, bad, unrecognized, unauthorized):
        # keyids for all the valid signatures
        self._good = good[:]
        # keyids for the invalid signatures (we had the key, and it failed).
        self._bad = bad[:]
        # keyids for signatures where we didn't recognize the key
        self._unrecognized = unrecognized[:]
        # keyids for signatures where we recognized the key, but it doesn't
        # seem to be allowed to sign this kind of document.
        self._unauthorized = unauthorized[:]

    def isValid(self, threshold=1):
        """Return true iff we got at least 'threshold' good signatures."""
        return len(self._good) >= threshold

    def mayNeedNewKeys(self):
        """Return true iff downloading a new set of keys might tip this
           signature status over to 'valid.'"""
        return len(self._unrecognized) or len(self._unauthorized)

def checkSignatures(signed, keyDB, role=None, path=None):
    """Given an object conformant to SIGNED_SCHEMA and a set of public keys
       in keyDB, verify the signed object is signed.  If 'role' and 'path'
       are provided, verify that the signing key has the correct role to
       sign this document as stored in 'path'.

       Returns a SignatureStatus.
    """

    SIGNED_SCHEMA.checkMatch(signed)

    goodSigs = []
    badSigs = []
    unknownSigs = []
    tangentialSigs = []

    signable = signed['signed']
    signatures = signed['signatures']

    d_obj = Crypto.Hash.SHA256.new()
    getDigest(signable, d_obj)
    digest = d_obj.digest()

    for signature in signatures:
        sig = signature['sig']
        keyid = signature['keyid']
        method = signature['method']

        try:
            key = keyDB.getKey(keyid)
        except KeyError:
            unknownSigs.append(keyid)
            continue

        try:
            result = key.checkSignature(method, sig, digest=digest)
        except thandy.UnknownMethod:
            continue

        if result:
            if role is not None:
                for r,p in key.getRoles():
                    if r == role and rolePathMatches(p, path):
                        break
                else:
                    tangentialSigs.append(sig)
                    continue

            goodSigs.append(keyid)
        else:
            badSigs.append(keyid)

    return SignatureStatus(goodSigs, badSigs, unknownSigs, tangentialSigs)

def _canonical_str_encoder(s):
    """Helper for encodeCanonical: encodes a string as the byte sequence
       expected for canonical JSON format.
    """
    s = '"%s"' % re.sub(r'(["\\])', r'\\\1', s)
    if isinstance(s, unicode):
        return s.encode("utf-8")
    else:
        return s

def _encodeCanonical(obj, outf):
    # Helper for encodeCanonical.  Older versions of json.encoder don't
    # even let us replace the separators.

    if isinstance(obj, basestring):
        outf(_canonical_str_encoder(obj))
    elif obj is True:
        outf("true")
    elif obj is False:
        outf("false")
    elif obj is None:
        outf("null")
    elif isinstance(obj, (int,long)):
        outf(str(obj))
    elif isinstance(obj, (tuple, list)):
        outf("[")
        if len(obj):
            for item in obj[:-1]:
                _encodeCanonical(item, outf)
                outf(",")
            _encodeCanonical(obj[-1], outf)
        outf("]")
    elif isinstance(obj, dict):
        outf("{")
        if len(obj):
            items = obj.items()
            items.sort()
            for k,v in items[:-1]:
                outf(_canonical_str_encoder(k))
                outf(":")
                _encodeCanonical(v, outf)
                outf(",")
            k, v = items[-1]
            outf(_canonical_str_encoder(k))
            outf(":")
            _encodeCanonical(v, outf)
        outf("}")
    else:
        raise thandy.FormatException("I can't encode %r"%obj)

def encodeCanonical(obj, outf=None):
    """Encode the object obj in canoncial JSon form, as specified at
       http://wiki.laptop.org/go/Canonical_JSON .  It's a restricted
       dialect of JSON in which keys are always lexically sorted,
       there is no whitespace, floats aren't allowed, and only quote
       and backslash get escaped.  The result is encoded in UTF-8, and
       the resulting bytes are passed to outf (if provided) in several
       calls, or joined into a string and returned.

       >>> encodeCanonical("")
       '""'
       >>> encodeCanonical([1, 2, 3])
       '[1,2,3]'
       >>> encodeCanonical([])
       '[]'
       >>> encodeCanonical({"A": [99]})
       '{"A":[99]}'
       >>> encodeCanonical({"x" : 3, "y" : 2})
       '{"x":3,"y":2}'
       >>> total = 0
       >>> def increment(s):
       ...   global total
       ...   total += len(s)
       ...
       >>> encodeCanonical({"x" : 3, "y" : 2, 'z' : [99,3]}, outf=increment)
       >>> total
       24
    """

    result = None
    if outf == None:
        result = [ ]
        outf = result.append

    _encodeCanonical(obj, outf)

    if result is not None:
        return "".join(result)

def getDigest(obj, digestObj=None):
    """Update 'digestObj' (typically a SHA256 object) with the digest of
       obj, first encoding it in canonical form if it's a JSON object,
       and taking its UTF-8 encoding if it's in unicode.  If digestObj
       is none, just compute and return the SHA256 hash.
    """
    useTempDigestObj = (digestObj == None)
    if useTempDigestObj:
        digestObj = Crypto.Hash.SHA256.new()

    if isinstance(obj, str):
        digestObj.update(obj)
    elif isinstance(obj, unicode):
        digestObj.update(obj.encode("utf-8"))
    else:
        encodeCanonical(obj, digestObj.update)

    if useTempDigestObj:
        return digestObj.digest()

def getFileDigest(f, digestObj=None):
    """Update 'digestObj' (typically a SHA256 object) with the digest
       of the file object (or filename) in f.  If digestObj is none,
       compute the SHA256 hash and return it.

       >>> s = "here is a long string"*1000
       >>> import cStringIO, Crypto.Hash.SHA256
       >>> h1 = Crypto.Hash.SHA256.new()
       >>> h2 = Crypto.Hash.SHA256.new()
       >>> getFileDigest(cStringIO.StringIO(s), h1)
       >>> h2.update(s)
       >>> h1.digest() == h2.digest()
       True
    """
    f_to_close = None
    if isinstance(f, basestring):
        f_to_close = f = open(f, 'rb')

    useTempDigestObj = (digestObj == None)
    if useTempDigestObj:
        digestObj = Crypto.Hash.SHA256.new()

    try:
        while 1:
            s = f.read(4096)
            if not s:
                break
            digestObj.update(s)
    finally:
        if f_to_close != None:
            f_to_close.close()

    if useTempDigestObj:
        return digestObj.digest()

def makeSignable(obj):
    """Return a new JSON object of type 'signed' wrapping 'obj', and containing
       no signatures.
    """
    return { 'signed' : obj, 'signatures' : [] }

def sign(signed, key):
    """Add an element to the signatures of 'signed', containing a new signature
       of the "signed" part using 'key'.  Replaces all previous signatures
       generated with 'key'.
    """

    SIGNED_SCHEMA.checkMatch(signed)

    signable = signed["signed"]
    signatures = signed['signatures']

    keyid = key.getKeyID()

    signatures = [ s for s in signatures if s['keyid'] != keyid ]
    newsignatures = key.sign(signable)

    for method, sig in newsignatures:
        signatures.append({ 'keyid' : keyid,
                            'method' : method,
                            'sig' : sig })

    signed['signatures'] = signatures

def formatTime(t):
    """Encode the time 't' in YYYY-MM-DD HH:MM:SS format.

    >>> formatTime(1221265172)
    '2008-09-13 00:19:32'
    """
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))

def parseTime(s):
    """Parse a time 's' in YYYY-MM-DD HH:MM:SS format."""
    try:
        return calendar.timegm(time.strptime(s, "%Y-%m-%d %H:%M:%S"))
    except ValueError:
        raise thandy.FormatException("Malformed time %r", s)

def formatBase64(h):
    """Return the base64 encoding of h with whitespace and = signs omitted."""
    return binascii.b2a_base64(h).rstrip("=\n ")

formatHash = formatBase64

def parseBase64(s):
    """Parse a base64 encoding with whitespace and = signs omitted. """
    extra = len(s) % 4
    if extra:
        padding = "=" * (4 - extra)
        s += padding
    try:
        return binascii.a2b_base64(s)
    except binascii.Error:
        raise thandy.FormatException("Invalid base64 encoding")

def parseHash(s):
    """Parse a base64-encoded digest.

       (This is just like paseBase64, but it checks the size.)
    """
    h = parseBase64(s)
    if len(h) != Crypto.Hash.SHA256.digest_size:
        raise thandy.FormatException("Bad hash length")
    return h

# Abbreviate the thandy.checkJson module here, since we're going to be
# using all of its members a lot here.
S = thandy.checkJson

#########
## These schemas describe, in OO constraint-checking form, all the Thandy
## data formats.

# A date, in YYYY-MM-DD HH:MM:SS format.
TIME_SCHEMA = S.RE(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')
# A hash, base64-encoded
HASH_SCHEMA = S.RE(r'[a-zA-Z0-9\+\/]{43}')

# A hexadecimal value.
HEX_SCHEMA = S.RE(r'[a-fA-F0-9]+')
# A base-64 encoded value
BASE64_SCHEMA = S.RE(r'[a-zA-Z0-9\+\/]+')
# An RSA key; subtype of PUBKEY_SCHEMA.
RSAKEY_SCHEMA = S.Obj(
    _keytype=S.Str("rsa"),
    e=BASE64_SCHEMA,
    n=BASE64_SCHEMA)
# An RSA key with private-key informartion: subtype of RSAKEY_SCHEMA.
RSAKEY_PRIVATE_SCHEMA = S.Obj(
    _keytype=S.Str("rsa"),
    e=BASE64_SCHEMA,
    n=BASE64_SCHEMA,
    d=BASE64_SCHEMA,
    p=BASE64_SCHEMA,
    q=BASE64_SCHEMA,
    u=BASE64_SCHEMA)
# Any public key.
PUBKEY_SCHEMA = S.Obj(
    _keytype=S.AnyStr())

KEYID_SCHEMA = HASH_SCHEMA
SIG_METHOD_SCHEMA = S.AnyStr()
RELPATH_SCHEMA = PATH_PATTERN_SCHEMA = S.AnyStr()
URL_SCHEMA = S.AnyStr()
VERSION_SCHEMA = S.ListOf(S.Any()) #XXXX WRONG
LENGTH_SCHEMA = S.Int(lo=0)

# A single signature of an object.  Indicates the signature, the id of the
# signing key, and the signing method.
SIGNATURE_SCHEMA = S.Obj(
    keyid=KEYID_SCHEMA,
    method=SIG_METHOD_SCHEMA,
    sig=BASE64_SCHEMA)

# A signed object.
SIGNED_SCHEMA = S.Obj(
    signed=S.Any(),
    signatures=S.ListOf(SIGNATURE_SCHEMA))

# The name of a role
ROLENAME_SCHEMA = S.AnyStr()

# A role: indicates that a key is allowed to certify a kind of
# document at a certain place in the repo.
ROLE_SCHEMA = S.Struct([ROLENAME_SCHEMA, PATH_PATTERN_SCHEMA], allowMore=True)

# A Keylist: indicates a list of live keys and their roles.
KEYLIST_SCHEMA = S.Obj(
    _type=S.Str("Keylist"),
    ts=TIME_SCHEMA,
    keys=S.ListOf(S.Obj(key=PUBKEY_SCHEMA, roles=S.ListOf(ROLE_SCHEMA))))

# A Mirrorlist: indicates all the live mirrors, and what documents they
# serve.
MIRRORLIST_SCHEMA = S.Obj(
    _type=S.Str("Mirrorlist"),
    ts=TIME_SCHEMA,
    mirrors=S.ListOf(S.Obj(name=S.AnyStr(),
                           urlbase=URL_SCHEMA,
                           contents=S.ListOf(PATH_PATTERN_SCHEMA),
                           weight=S.Int(lo=0),
                           )))

# A timestamp: indicates the lastest versions of all top-level signed objects.
TIMESTAMP_SCHEMA = S.Obj(
    _type = S.Str("Timestamp"),
    at = TIME_SCHEMA,
    m = S.Struct([TIME_SCHEMA, HASH_SCHEMA], [LENGTH_SCHEMA], allowMore=True),
    k = S.Struct([TIME_SCHEMA, HASH_SCHEMA], [LENGTH_SCHEMA], allowMore=True),
    b = S.DictOf(keySchema=S.AnyStr(),
            valSchema=
                 S.Struct([ VERSION_SCHEMA, RELPATH_SCHEMA, TIME_SCHEMA, HASH_SCHEMA ], [LENGTH_SCHEMA], allowMore=True))
    )

# A Bundle: lists a bunch of packages that should be updated in tandem
BUNDLE_SCHEMA = S.Obj(
   _type=S.Str("Bundle"),
   at=TIME_SCHEMA,
   name=S.AnyStr(),
   os=S.AnyStr(),
   arch=S.Opt(S.AnyStr()),
   version=VERSION_SCHEMA,
   location=RELPATH_SCHEMA,
   packages=S.ListOf(S.Obj(
                    name=S.AnyStr(),
                    version=VERSION_SCHEMA,
                    path=RELPATH_SCHEMA,
                    hash=HASH_SCHEMA,
                    length=LENGTH_SCHEMA,
                    order=S.Struct([S.Int(), S.Int(), S.Int()]),
                    optional=S.Opt(S.Bool()),
                    gloss=S.DictOf(S.AnyStr(), S.AnyStr()),
                    longgloss=S.DictOf(S.AnyStr(), S.AnyStr()))))

def checkWinRegistryKeyname(keyname):
    """Check keyname for superficial well-formedness as a win32 registry entry
       name."""
    hkey, rest = keyname.split("\\", 1)
    key, value = rest.rsplit("\\", 1)
    if hkey not in [ "HKEY_CURRENT_CONFIG",
                     "HKEY_CURRENT_USER",
                     "HKEY_LOCAL_MACHINE" ]:
        raise thandy.FormatException("Bad hkey on registry entry.")
    elif not key or not value:
        raise thandy.FormatException("Bad registry entry.")

# A string holding the name of a windows registry key
REGISTRY_KEY_SCHEMA = S.Func(checkWinRegistryKeyname)

CHECK_ITEM_SCHEMA = S.TaggedObj(
    tagName='check_type',
    tagIsOptional=True,
    registry=S.Obj(registry_ent=S.Struct([REGISTRY_KEY_SCHEMA, S.AnyStr()])),
    db=S.Obj(item_name=S.AnyStr(),
             item_version=S.Any() #XXXX wrong!
             ),
    rpm=S.Obj(rpm_version=S.AnyStr()))

INSTALL_ITEM_SCHEMA = S.TaggedObj(
    tagName='install_type',
    tagIsOptional=True,
    command=S.Obj(cmd_install=S.ListOf(S.AnyStr()),
                  cmd_remove=S.Opt(S.ListOf(S.AnyStr()))),
    rpm=S.Obj())

OBSOLETE_EXE_FORMAT_ITEM_SCHEMA = S.Obj(
    registry_ent=S.Opt(S.Struct([REGISTRY_KEY_SCHEMA, S.AnyStr()])),
    exe_args=S.ListOf(S.AnyStr()))
OBSOLETE_RPM_FORMAT_ITEM_SCHEMA = S.Obj(
    rpm_version=S.AnyStr())

ITEM_INFO_SCHEMA = S.AllOf([CHECK_ITEM_SCHEMA, INSTALL_ITEM_SCHEMA])

ITEM_SCHEMA = S.Struct([RELPATH_SCHEMA, HASH_SCHEMA],
                       [ITEM_INFO_SCHEMA, LENGTH_SCHEMA],
                       allowMore=True)

def checkPackageFormatConsistency(obj):
    format = obj.get('format')
    if format:
        formatSchema = { 'exe' : OBSOLETE_EXE_FORMAT_ITEM_SCHEMA,
                         'rpm' : OBSOLETE_RPM_FORMAT_ITEM_SCHEMA }.get(format)
        if formatSchema:
            for f in obj['files']:
                if len(f) >= 3:
                    formatSchema.checkMatch(f[2])

PACKAGE_SCHEMA = S.Obj(
            _type=S.Str("Package"),
            name=S.AnyStr(),
            location=RELPATH_SCHEMA,
            version=VERSION_SCHEMA,
            format=S.Opt(S.AnyStr()),
            ts=TIME_SCHEMA,
            files=S.ListOf(S.Struct([RELPATH_SCHEMA, HASH_SCHEMA],
                                    allowMore=True)),
            shortdesc=S.DictOf(S.AnyStr(), S.AnyStr()),
            longdesc=S.DictOf(S.AnyStr(), S.AnyStr()))

PACKAGE_SCHEMA = S.Func(checkPackageFormatConsistency, PACKAGE_SCHEMA)

ALL_ROLES = ('timestamp', 'mirrors', 'bundle', 'package', 'master')

class Keylist(KeyDB):
    """A list of keys, as extracted from a Thandy keys.txt JSon file.

       This class extends KeyDB, so you can acces keys more easily.
    """
    def __init__(self):
        KeyDB.__init__(self)

    def addFromKeylist(self, obj, allowMasterKeys=False):
        for keyitem in obj['keys']:
            key = keyitem['key']
            roles = keyitem['roles']

            try:
                key = thandy.keys.RSAKey.fromJSon(key)
            except thandy.FormatException, e:
                print e
                #LOG skipping key.
                continue

            for r,p in roles:
                if r == 'master' and not allowMasterKeys:
                    #LOG
                    continue
                if r not in ALL_ROLES:
                    continue
                key.addRole(r,p)

            self.addKey(key)

class StampedInfo:
    """This class holds a single entry in a timestamp file.  Each
       StampedInfo says when a file was last modified, and what its
       hash was.  It may also provide useful info about where to find it,
       its version, its length, and so on.
    """
    ## _ts -- the time when the file was last modified
    ## _hash -- the hash of the most recent version of the file
    ## _version -- version of the most recent file. May be None
    ## _relpath -- where to find this file in the repository
    ## _length -- the length of the file
    def __init__(self, ts, hash, version=None, relpath=None, length=None):
        self._ts = ts
        self._hash = hash
        self._version = version
        self._relpath = relpath
        self._length = length

    @staticmethod
    def fromJSonFields(timeStr, hashStr, length=None):
        t = parseTime(timeStr)
        h = parseHash(hashStr)
        return StampedInfo(t, h, length=length)

    def getHash(self):
        return self._hash

    def getRelativePath(self):
        return self._relpath

    def getLength(self):
        return self._length

class TimestampFile:
    """This class holds all the fields parsed from a thandy timestamp file."""
    ## _time -- the time when this file was generated
    ## _mirrorListInfo -- a StampedInfo for the keylist.
    ## _keyListInfo -- a StampedInfo for the mirrorlist
    ## _bundleInfo -- map from bundle name to StampedInfo
    def __init__(self, at, mirrorlistinfo, keylistinfo, bundleinfo):
        self._time = at
        self._mirrorListInfo = mirrorlistinfo
        self._keyListInfo = keylistinfo
        self._bundleInfo = bundleinfo

    @staticmethod
    def fromJSon(obj):
        # must be validated.
        at = parseTime(obj['at'])
        # We slice these lists because we want to support old thandys
        # that didn't include the length on these, and new ones that
        # might include more fields
        m = StampedInfo.fromJSonFields(*obj['m'][:3])
        k = StampedInfo.fromJSonFields(*obj['k'][:3])
        b = {}
        for name, bundle in obj['b'].iteritems():
            v = bundle[0]
            rp = bundle[1]
            t = parseTime(bundle[2])
            h = parseHash(bundle[3])
            ln = None
            if len(bundle) > 4:
                ln = bundle[4]
            b[name] = StampedInfo(t, h, v, rp, ln)

        return TimestampFile(at, m, k, b)

    def getTime(self):
        return self._time

    def getMirrorlistInfo(self):
        return self._mirrorListInfo

    def getKeylistInfo(self):
        return self._keyListInfo

    def getBundleInfo(self, name):
        return self._bundleInfo[name]

    def getBundleInfos(self):
        return self._bundleInfo

def readConfigFile(fname, needKeys=(), optKeys=(), preload={}):
    """Read a configuration file from 'fname'.  A configuration file is a
       python script that runs in a temporary namespace prepopulated
       with the contents of 'reload'.  It is a thandy.FormatException
       if the file finishes executation without setting every variable
       listed in 'needKeys'.  These settings, plus any variables whose names
       are listed in 'optKeys', are returned in a new dict.
    """
    parsed = preload.copy()
    result = {}
    execfile(fname, parsed)

    for k in needKeys:
        try:
            result[k] = parsed[k]
        except KeyError:
            raise thandy.FormatException("Missing value for %s in %s"%k,fname)

    for k in optKeys:
        try:
            result[k] = parsed[k]
        except KeyError:
            pass

    return result

def makePackageObj(config_fname, package_fname):
    """Given a description of a thandy package in config_fname, and the
       name of the one file (only one is supported now!) in package_fname,
       return a new unsigned package object.
    """
    preload = {}
    shortDescs = {}
    longDescs = {}
    def ShortDesc(lang, val): shortDescs[lang] = val
    def LongDesc(lang, val): longDescs[lang] = val
    #XXXX handle multiple files.
    preload = { 'ShortDesc' : ShortDesc, 'LongDesc' : LongDesc }
    r = readConfigFile(config_fname,
                       ['name',
                        'version',
                        'format',
                        'location',
                        'relpath',
                        ], ['rpm_version', 'exe_args',
                            'exe_registry_ent',
                            'db_key', 'db_val',
                            'command_install', 'command_remove',
                            ], preload)

    f = open(package_fname, 'rb')
    digest = getFileDigest(f)
    f.close()
    f_len = os.stat(package_fname).st_size

    # Check fields!
    extra = {}
    result = { '_type' : "Package",
               'ts' : formatTime(time.time()),
               'name' : r['name'],
               'location' : r['location'], #DOCDOC
               'version' : r['version'],
               'format' : r['format'],
               'files' : [ [ r['relpath'], formatHash(digest), extra, f_len ] ],
               'shortdesc' : shortDescs,
               'longdesc' : longDescs
             }

    format = r['format']
    if format == 'rpm':
        if not r.get('rpm_version'):
            raise thandy.FormatException("missing rpm_version value")
        extra['rpm_version'] = r['rpm_version']
        extra['check_type'] = 'rpm'
        extra['install_type'] = 'rpm'
    elif format == 'exe':
        if not r.get('exe_args'):
            raise thandy.FormatException("missing exe_args value")
        extra['exe_args'] = r['exe_args']
        if not r.get('cmd_install'):
            extra['install_type'] = 'command'
            extra['cmd_install'] = [ "${FILE}" ] + r['exe_args']

    if r.get('command_install'):
        extra['install_type'] = 'command'
        extra['cmd_install'] = r['command_install']
        if r.get('command_remove'):
            extra['cmd_remove'] = r['command_remove']

    if r.get('exe_registry_ent'):
        if len(r['exe_registry_ent']) != 2:
            raise thandy.FormatException("Bad length on exe_registry_ent")
        regkey, regval = r['exe_registry_ent']
        checkWinRegistryKeyname(regkey)
        if not isinstance(regval, basestring):
            raise thandy.FormatException("Bad version on exe_registry_ent")
        extra['registry_ent'] = [ regkey, regval ]
        extra['check_type'] = 'registry'
    elif r.get('db_key'):
        extra['item_name'] = r['db_key']
        extra['item_version'] = r['db_val']
        extra['check_type'] = 'db'

    PACKAGE_SCHEMA.checkMatch(result)

    return result

def makeBundleObj(config_fname, getPackage, getPackageLength):
    """Given a description of a thandy  bundle in config_fname,
       return a new unsigned bundle object.  getPackage must be a function
       returning a package object for every package the bundle requires
       when given the package's name as input.  getPacakgeLength
       must be a function returning the length of the package file.
    """
    packages = []
    def ShortGloss(lang, val): packages[-1]['gloss'][lang] = val
    def LongGloss(lang, val): packages[-1]['longgloss'][lang] = val
    def Package(name, order, version=None, path=None, optional=False):
        packages.append({'name' : name,
                         'version' : version,
                         'path' : path,
                         'order' : order,
                         'optional' : optional,
                         'gloss' : {},
                         'longgloss' : {} })
    preload = { 'ShortGloss' : ShortGloss, 'LongGloss' : LongGloss,
                'Package' : Package }
    r = readConfigFile(config_fname,
                       ['name',
                        'os',
                        'version',
                        'location',
                        ], ['arch'], preload)

    result = { '_type' : "Bundle",
               'at' : formatTime(time.time()),
               'name' : r['name'],
               'os' : r['os'],
               'version' : r['version'],
               'location' : r['location'],
               'packages' : packages }
    if r.has_key('arch'):
        result['arch'] = r['arch']

    for p in packages:
        try:
            pkginfo = getPackage(p['name'])
        except KeyError:
            raise thandy.FormatException("No such package as %s"%p['name'])

        p['hash'] = formatHash(getDigest(pkginfo))
        p['length'] = getPackageLength(p['name'])
        if p['path'] == None:
            p['path'] = pkginfo['location']
        if p['version'] == None:
            p['version'] = pkginfo['version']

    BUNDLE_SCHEMA.checkMatch(result)
    return result

def versionIsNewer(v1, v2):
    """Return true if version v1 is newer than v2.  Both versions are
       given as lists of version components.
       >>> versionIsNewer([1,2,3], [1,2,3,4])
       False
       >>> versionIsNewer([1,2,3,5], [1,2,3,4])
       True
       >>> versionIsNewer([1,3,3,5], [1,2,3,5])
       True
    """
    return v1 > v2

def getBundleKey(bundlePath):
    """
       Return all parts of a bundle's "key" as used in a timestamp file,
       given its full filename.

       >>> getBundleKey("/bundleinfo/tor-browser/win32/some-file-name.txt")
       '/bundleinfo/tor-browser/win32/'
    """
    # No, we can't use "os.path.directory" or "os.path.split".  Those are
    # OD-dependent, and all of our paths are in Unix format.
    idx = bundlePath.rindex("/")
    return bundlePath[:idx+1]

def makeTimestampObj(mirrorlist_obj, mirrorlist_len,
                     keylist_obj, keylist_len,
                     bundle_objs):
    """Return a new unsigned timestamp object for a given set of inputs,
       where mirrorlist_obj and mirrorlist_len are a (signed, unencoded)
       mirror list, and its length on disk; keylist_obj and keylist_len
       are the same for the key list, and bundle_objs is a list of
       (object, length) tuples for all the bundles.
    """
    result = { '_type' : 'Timestamp',
               'at' : formatTime(time.time()) }
    result['m'] = [ mirrorlist_obj['ts'],
                    formatHash(getDigest(mirrorlist_obj)),
                    mirrorlist_len ]
    result['k'] = [ keylist_obj['ts'],
                    formatHash(getDigest(keylist_obj)),
                    keylist_len ]
    result['b'] = bundles = {}
    for bundle, bundleLen in bundle_objs:
        k = getBundleKey(bundle['location'])
        v = bundle['version']
        entry = [ v, bundle['location'], bundle['at'], formatHash(getDigest(bundle)), bundleLen ]
        if not bundles.has_key(k) or versionIsNewer(v, bundles[k][0]):
            bundles[k] = entry

    TIMESTAMP_SCHEMA.checkMatch(result)

    return result

class MirrorInfo:
    """A MirrorInfo holds the parsed value of a thandy mirror list's entry
       for a single mirror."""
    def __init__(self, name, urlbase, contents, weight):
        self._name = name
        self._urlbase = urlbase
        self._contents = contents
        self._weight = weight

    def canServeFile(self, fname):
        for c in self._contents:
            if rolePathMatches(c, fname):
                return True
        return False

    def getFileURL(self, fname):
        if self._urlbase[-1] == '/':
            return self._urlbase+fname
        else:
            return "%s/%s" % (self._urlbase, fname)

    def format(self):
        return { 'name' : self._name,
                 'urlbase' : self._urlbase,
                 'contents' : self._contents,
                 'weight' : self._weight }

def makeMirrorListObj(mirror_fname):
    """Return a new unsigned mirrorlist object for the mirrors described in
       'mirror_fname'.
    """
    mirrors = []
    def Mirror(*a, **kw): mirrors.append(MirrorInfo(*a, **kw))
    preload = {'Mirror' : Mirror}
    r = readConfigFile(mirror_fname, (), (), preload)
    result = { '_type' : "Mirrorlist",
               'ts' : formatTime(time.time()),
               'mirrors' : [ m.format() for m in mirrors ] }

    MIRRORLIST_SCHEMA.checkMatch(result)
    return result

def makeKeylistObj(keylist_fname, includePrivate=False):
    """Return a new unsigned keylist object for the keys described in
       'mirror_fname'.
    """
    keys = []
    def Key(obj): keys.append(obj)
    preload = {'Key': Key}
    r = readConfigFile(keylist_fname, (), (), preload)

    klist = []
    for k in keys:
        k = thandy.keys.RSAKey.fromJSon(k)
        if includePrivate and not k.isPrivateKey():
            raise thandy.FormatException("Private key information not found.")

        klist.append({'key': k.format(private=includePrivate), 'roles' : k.getRoles() })

    result = { '_type' : "Keylist",
               'ts' : formatTime(time.time()),
               'keys' : klist }

    KEYLIST_SCHEMA.checkMatch(result)
    return result

#XXXX could use taggedobj.  Defer till this has a unit test.
SCHEMAS_BY_TYPE = {
    'Keylist' : KEYLIST_SCHEMA,
    'Mirrorlist' : MIRRORLIST_SCHEMA,
    'Timestamp' : TIMESTAMP_SCHEMA,
    'Bundle' : BUNDLE_SCHEMA,
    'Package' : PACKAGE_SCHEMA,
    }

def checkSignedObj(obj, keydb=None):
    """Given a signed object, check whether it is well-formed and correctly
       signed with some key in keydb having the appropriate role.  On
       success, returns a SignatureStatus, the rule used to sign it,
       and the object's path in the repository.
    """

    SIGNED_SCHEMA.checkMatch(obj)
    try:
        tp = obj['signed']['_type']
    except KeyError:
        raise thandy.FormatException("Untyped object")
    try:
        schema = SCHEMAS_BY_TYPE[tp]
    except KeyError:
        raise thandy.FormatException("Unrecognized type %r" % tp)
    schema.checkMatch(obj['signed'])

    if tp == 'Keylist':
        role = "master"
        path = "/meta/keys.txt"
    elif tp == 'Mirrorlist':
        role = "mirrors"
        path = "/meta/mirrors.txt"
    elif tp == "Timestamp":
        role = 'timestamp'
        path = "/meta/timestamp.txt"
    elif tp == 'Bundle':
        role = 'bundle'
        path = obj['signed']['location']
    elif tp == 'Package':
        role = 'package'
        path = obj['signed']['location']
    else:
        raise ValueError("Unknown signed object type %r"%tp)

    ss = None
    if keydb is not None:
        ss = checkSignatures(obj, keydb, role, path)

    return ss, role, path
