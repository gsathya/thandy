# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import simplejson
import time
import re
import binascii
import calendar

import thandy.checkJson

import Crypto.Hash.SHA256

class KeyDB:
    """A KeyDB holds public keys, indexed by their key IDs."""
    def __init__(self):
        self._keys = {}
    def addKey(self, k):
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
        return self._keys[keyid]
    def getKeysByRole(self, role, path):
        results = []
        for key in self._keys.itervalues():
            for r,p in key.getRoles():
                if r == role:
                    if rolePathMatches(p, path):
                        results.append(key)
        return results

    def getKeysFuzzy(self, keyid):
        r = []
        for k,v in self._keys.iteritems():
            if k.startswith(keyid):
                r.append(v)
        return r
    def iterkeys(self):
        return self._keys.itervalues()

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
       in keyDB, verify the signed object in 'signed'."""

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

        if result == True:
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

def _encodeCanonical_makeiter(obj):
    """Return an iterator to encode 'obj' canonically, and a nil
       cleanup function.  Works with newer versions of simplejson that
       have a _make_iterencode method.
    """
    def default(o):
        raise TypeError("Can't encode %r", o)
    def floatstr(o):
        raise TypeError("Floats not allowed.")
    def canonical_str_encoder(s):
        return '"%s"' % re.sub(r'(["\\])', r'\\\1', s)

    # XXX This is, alas, a hack.  I'll submit a canonical JSon patch to
    # the simplejson folks.
    iterator = simplejson.encoder._make_iterencode(
        None, default, canonical_str_encoder, None, floatstr,
        ":", ",", True, False, True)(obj, 0)

    return iterator, lambda:None

def _encodeCanonical_monkeypatch(obj):
    """Return an iterator to encode 'obj' canonically, and a cleanup
       function to un-monkeypatch simplejson.  Works with older
       versions of simplejson.  This is not threadsafe wrt other
       invocations of simplejson, so until we're all upgraded, no
       doing canonical encodings outside of the main thread.
    """
    def default(o):
        raise TypeError("Can't encode %r", o)
    save_floatstr = simplejson.encoder.floatstr
    save_encode_basestring = simplejson.encoder.encode_basestring
    def floatstr(o):
        raise TypeError("Floats not allowed.")
    def canonical_str_encoder(s):
        return '"%s"' % re.sub(r'(["\\])', r'\\\1', s)
    simplejson.encoder.floatstr = floatstr
    simplejson.encoder.encode_basestring = canonical_str_encoder
    def unpatch():
        simplejson.encoder.floatstr = save_floatstr
        simplejson.encoder.encode_basestring = save_encode_basestring

    encoder = simplejson.encoder.JSONEncoder(ensure_ascii=False,
                                             check_circular=False,
                                             allow_nan=False,
                                             sort_keys=True,
                                             separators=(",",":"),
                                             default=default)
    return encoder.iterencode(obj), unpatch

if hasattr(simplejson.encoder, "_make_iterencode"):
    _encodeCanonical = _encodeCanonical_makeiter
else:
    _encodeCanonical = _encodeCanonical_monkeypatch

def encodeCanonical(obj, outf=None):
    """Encode the object obj in canoncial JSon form, as specified at
       http://wiki.laptop.org/go/Canonical_JSON .  It's a restricted
       dialect of json in which keys are always lexically sorted,
       there is no whitespace, floats aren't allowed, and only quote
       and backslash get escaped.  The result is encoded in UTF-8,
       and the resulting bits are passed to outf (if provided), or joined
       into a string and returned.

       >>> encodeCanonical("")
       '""'
       >>> encodeCanonical([1, 2, 3])
       '[1,2,3]'
       >>> encodeCanonical({"x" : 3, "y" : 2})
       '{"x":3,"y":2}'
    """

    result = None
    if outf == None:
        result = [ ]
        outf = result.append

    iterator, cleanup = _encodeCanonical(obj)

    try:
        for u in iterator:
            outf(u.encode("utf-8"))
    finally:
        cleanup()
    if result is not None:
        return "".join(result)

def getDigest(obj, digestObj=None):
    """Update 'digestObj' (typically a SHA256 object) with the digest of
       the canonical json encoding of obj.  If digestObj is none,
       compute the SHA256 hash and return it.

       DOCDOC string equivalence.
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
    """Update 'digestObj' (typically a SHA256 object) with the digest of
       the file object in f.  If digestObj is none, compute the SHA256
       hash and return it.

       >>> s = "here is a long string"*1000
       >>> import cStringIO, Crypto.Hash.SHA256
       >>> h1 = Crypto.Hash.SHA256.new()
       >>> h2 = Crypto.Hash.SHA256.new()
       >>> getFileDigest(cStringIO.StringIO(s), h1)
       >>> h2.update(s)
       >>> h1.digest() == h2.digest()
       True
    """
    useTempDigestObj = (digestObj == None)
    if useTempDigestObj:
        digestObj = Crypto.Hash.SHA256.new()

    while 1:
        s = f.read(4096)
        if not s:
            break
        digestObj.update(s)

    if useTempDigestObj:
        return digestObj.digest()

def makeSignable(obj):
    return { 'signed' : obj, 'signatures' : [] }

def sign(signed, key):
    """Add an element to the signatures of 'signed', containing a new signature
       of the "signed" part.
    """

    SIGNED_SCHEMA.checkMatch(signed)

    signable = signed["signed"]
    signatures = signed['signatures']

    keyid = key.getKeyID()

    signatures = [ s for s in signatures if s['keyid'] != keyid ]

    method, sig = key.sign(signable)
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
        raise thandy.FormatError("Malformed time %r", s)

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
        raise thandy.FormatError("Invalid base64 encoding")

def parseHash(s):
    h = parseBase64(s)
    if len(h) != Crypto.Hash.SHA256.digest_size:
        raise thandy.FormatError("Bad hash length")
    return h

S = thandy.checkJson

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
# Any public key.
PUBKEY_SCHEMA = S.Obj(
    _keytype=S.AnyStr())

KEYID_SCHEMA = HASH_SCHEMA
SIG_METHOD_SCHEMA = S.AnyStr()
RELPATH_SCHEMA = PATH_PATTERN_SCHEMA = S.AnyStr()
URL_SCHEMA = S.AnyStr()
VERSION_SCHEMA = S.ListOf(S.Any()) #XXXX WRONG

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

ROLENAME_SCHEMA = S.AnyStr()

# A role: indicates that a key is allowed to certify a kind of
# document at a certain place in the repo.
ROLE_SCHEMA = S.Struct([ROLENAME_SCHEMA, PATH_PATTERN_SCHEMA])

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
    m = S.Struct([TIME_SCHEMA, HASH_SCHEMA]),
    k = S.Struct([TIME_SCHEMA, HASH_SCHEMA]),
    b = S.DictOf(keySchema=S.AnyStr(),
            valSchema=
                 S.Struct([ VERSION_SCHEMA, RELPATH_SCHEMA, TIME_SCHEMA, HASH_SCHEMA ]))
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
                    order=S.Struct([S.Int(), S.Int(), S.Int()]),
                    optional=S.Opt(S.Bool()),
                    gloss=S.DictOf(S.AnyStr(), S.AnyStr()),
                    longgloss=S.DictOf(S.AnyStr(), S.AnyStr()))))

PACKAGE_SCHEMA = S.Obj(
            _type=S.Str("Package"),
            name=S.AnyStr(),
            location=RELPATH_SCHEMA,
            version=VERSION_SCHEMA,
            format=S.Obj(),
            ts=TIME_SCHEMA,
            files=S.ListOf(S.Struct([RELPATH_SCHEMA, HASH_SCHEMA])),
            shortdesc=S.DictOf(S.AnyStr(), S.AnyStr()),
            longdesc=S.DictOf(S.AnyStr(), S.AnyStr()))

ALL_ROLES = ('timestamp', 'mirrors', 'bundle', 'package', 'master')

class Key:
    #XXXX UNUSED.
    def __init__(self, key, roles=()):
        self.key = key
        self.roles = []
        for r,p in roles:
            self.addRole(r,p)

    def addRole(self, role, path):
        assert role in ALL_ROLES
        self.roles.append((role, path))

    def getRoles(self):
        return self.roles

    @staticmethod
    def fromJSon(obj):
        # must match PUBKEY_SCHEMA
        keytype = obj['_keytype']
        if keytype == 'rsa':
            return Key(thandy.keys.RSAKey.fromJSon(obj))

        if typeattr == 'rsa':
            key = thandy.keys.RSAKey.fromSExpression(sexpr)
            if key is not None:
                return Key(key)
        else:
            return None

    def format(self):
        return self.key.format()

    def getKeyID(self):
        return self.key.getKeyID()

    def sign(self, sexpr=None, digest=None):
        return self.key.sign(sexpr, digest=digest)

    def checkSignature(self, method, data, signatute):
        ok = self.key.checkSignature(method, data, signature)
        # XXXX CACHE HERE.
        return ok

class Keylist(KeyDB):
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
    def __init__(self, ts, hash, version=None, relpath=None):
        self._ts = ts
        self._hash = hash
        self._version = version
        self._relpath = relpath

    @staticmethod
    def fromJSonFields(timeStr, hashStr):
        t = parseTime(timeStr)
        h = parseHash(hashStr)
        return StampedInfo(t, h)

    def getHash(self):
        return self._hash

    def getRelativePath(self):
        return self._relpath

class TimestampFile:
    def __init__(self, at, mirrorlistinfo, keylistinfo, bundleinfo):
        self._time = at
        self._mirrorListInfo = mirrorlistinfo
        self._keyListInfo = keylistinfo
        self._bundleInfo = bundleinfo

    @staticmethod
    def fromJSon(obj):
        # must be validated.
        at = parseTime(obj['at'])
        m = StampedInfo.fromJSonFields(*obj['m'][:2])
        k = StampedInfo.fromJSonFields(*obj['k'][:2])
        b = {}
        for name, bundle in obj['b'].iteritems():
            v = bundle[0]
            rp = bundle[1]
            t = parseTime(bundle[2])
            h = parseHash(bundle[3])
            b[name] = StampedInfo(t, h, v, rp)

        return TimestampFile(at, m, k, b)

    def getTime(self):
        return self._time

    def getMirrorlistInfo(self):
        return self._mirrorListInfo

    def getKeylistInfo(self):
        return self._keyListInfo

    def getBundleInfo(self, name):
        return self._bundleInfo[name]

def readConfigFile(fname, needKeys=(), optKeys=(), preload={}):
    parsed = preload.copy()
    result = {}
    execfile(fname, parsed)

    for k in needKeys:
        try:
            result[k] = parsed[k]
        except KeyError:
            raise thandy.FormatError("Missing value for %s in %s"%k,fname)

    for k in optKeys:
        try:
            result[k] = parsed[k]
        except KeyError:
            pass

    return result

def makePackageObj(config_fname, package_fname):
    preload = {}
    shortDescs = {}
    longDescs = {}
    def ShortDesc(lang, val): shortDescs[lang] = val
    def LongDesc(lang, val): longDescs[lang] = val
    preload = { 'ShortDesc' : ShortDesc, 'LongDesc' : LongDesc }
    r = readConfigFile(config_fname,
                       ['name',
                        'version',
                        'format',
                        'location',
                        'relpath',
                        ], (), preload)

    f = open(package_fname, 'rb')
    digest = getFileDigest(f)

    # Check fields!
    result = { '_type' : "Package",
               'ts' : formatTime(time.time()),
               'name' : r['name'],
               'location' : r['location'], #DOCDOC
               'version' : r['version'],
               'format' : r['format'],
               'files' : [ [ r['relpath'], formatHash(digest) ] ],
               'shortdesc' : shortDescs,
               'longdesc' : longDescs
             }

    PACKAGE_SCHEMA.checkMatch(result)

    return result

def makeBundleObj(config_fname, getPackage):
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
        if p['path'] == None:
            p['path'] = pkginfo['location']
        if p['version'] == None:
            p['version'] = pkginfo['version']
        if p['

        except KeyError:
            raise thandy.FormatException("No such package as %s"%p['path'])

    BUNDLE_SCHEMA.checkMatch(result)
    return result

def versionIsNewer(v1, v2):
    return v1 > v2

def makeTimestampObj(mirrorlist_obj, keylist_obj,
                     bundle_objs):
    result = { '_type' : 'Timestamp',
               'at' : formatTime(time.time()) }
    result['m'] = [ mirrorlist_obj['ts'],
                    formatHash(getDigest(mirrorlist_obj)) ]
    result['k'] = [ keylist_obj['ts'],
                    formatHash(getDigest(keylist_obj)) ]
    result['b'] = bundles = {}
    for bundle in bundle_objs:
        name = bundle['name']
        v = bundle['version']
        entry = [ v, bundle['location'], bundle['at'], formatHash(getDigest(bundle)) ]
        if not bundles.has_key(name) or versionIsNewer(v, bundles[name][0]):
            bundles[name] = entry

    TIMESTAMP_SCHEMA.checkMatch(result)

    return result

class MirrorInfo:
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
    keys = []
    def Key(obj): keys.append(obj)
    preload = {'Key': Key}
    r = readConfigFile(keylist_fname, (), (), preload)

    klist = []
    for k in keys:
        k = thandy.keys.RSAKey.fromJSon(k)
        klist.append({'key': k.format(private=includePrivate), 'roles' : k.getRoles() })

    result = { '_type' : "Keylist",
               'ts' : formatTime(time.time()),
               'keys' : klist }

    KEYLIST_SCHEMA.checkMatch(result)
    return result

SCHEMAS_BY_TYPE = {
    'Keylist' : KEYLIST_SCHEMA,
    'Mirrorlist' : MIRRORLIST_SCHEMA,
    'Timestamp' : TIMESTAMP_SCHEMA,
    'Bundle' : BUNDLE_SCHEMA,
    'Package' : PACKAGE_SCHEMA,
    }

def checkSignedObj(obj, keydb=None):
    # Returns signaturestatus, role, path on sucess.

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
        print tp
        raise "Foo"

    ss = None
    if keydb is not None:
        ss = checkSignatures(obj, keydb, role, path)

    return ss, role, path
