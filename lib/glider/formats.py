
import sexp.access
import sexp.encode
import time
import re

class FormatException(Exception):
    pass

class KeyDB:
    def __init__(self):
        self.keys = {}
    def addKey(self, k):
        self.keys[k.getKeyID()] = k
    def getKey(self, keyid):
        return self.keys[keyid]

_rolePathCache = {}
def rolePathMatches(rolePath, path):
    """

    >>> rolePathMatches("a/b/c/", "a/b/c/")
    True
    >>> rolePathMatches("**/c.*", "a/b/c.txt")
    True
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
        rolePath = re.sub(r'/+', '/', rolePath)
        rolePath = re.escape(rolePath).replace(r'\*\*', r'.*')
        rolePath = rolePath.replace(r'\*', r'[^/]*')
        rolePath += "$"
        regex = _rolePathCache[rolePath] = re.compile(rolePath)
    return regex.match(path) != None

def checkSignatures(signed, keyDB, role, path):
    goodSigs = []
    badSigs = []
    unknownSigs = []
    tangentialSigs = []

    assert signed[0] == "signed"
    data = signed[1]

    d_obj = Crypto.Hash.SHA256.new()
    sexp.encode.hash_canonical(data, d_obj)
    digest = d_obj.digest()

    for signature in sexp.access.s_children(signed, "signature"):
        attrs = signature[1]
        sig = attrs[2]
        keyid = s_child(attrs, "keyid")[1]
        try:
            key = keyDB.getKey(keyid)
        except KeyError:
            unknownSigs.append(keyid)
            continue
        method = s_child(attrs, "method")[1]
        try:
            result = key.checkSignature(method, sig, digest=digest)
        except UnknownMethod:
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

    return goodSigs, badSigs, unknownSigs, tangentialSigs

def sign(signed, key):
    assert sexp.access.s_tag(signed) == 'signed'
    s = signed[1]
    keyid = key.keyID()

    oldsignatures = [ s for s in signed[2:] if s_child(s[1], "keyid") != keyid ]
    signed[2:] = oldsignatures

    for method, sig in key.sign(s):
        signed.append(['signature', [['keyid', keyid], ['method', method]],
                       sig])

def formatTime(t):
    """
    >>> formatTime(1221265172)
    '2008-09-13 00:19:32'
    """
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))

def parseTime(s):
    return time.timegm(time.strptime(s, "%Y-%m-%d %H:%M:%S"))

def _parseSchema(s, t=None):
    sexpr = sexp.parse.parse(s)
    schema = sexp.access.parseSchema(sexpr, t)
    return schema

SCHEMA_TABLE = { }

PUBKEY_TEMPLATE = r"""
  (=pubkey ((:unordered (=type .) (:anyof (. _)))) _)
"""

SCHEMA_TABLE['PUBKEY'] = _parseSchema(PUBKEY_TEMPLATE)

TIME_TEMPLATE = r"""/\{d}4-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/"""

SCHEMA_TABLE['TIME'] = sexp.access.parseSchema(TIME_TEMPLATE)

ATTRS_TEMPLATE = r"""(:anyof (_ *))"""

SCHEMA_TABLE['ATTRS'] = _parseSchema(ATTRS_TEMPLATE)

SIGNED_TEMPLATE = r"""
 (=signed
   _
   (:someof
     (=signature ((:unordered
                    (=keyid _) (=method _) .ATTRS)) _)
   )
 )"""

SIGNED_SCHEMA = _parseSchema(SIGNED_TEMPLATE, SCHEMA_TABLE)

KEYLIST_TEMPLATE = r"""
 (=keylist
   (=ts .TIME)
   (=keys
     (:anyof
       (=key ((:unordered (=roles (:someof (. .))) .ATTRS)) _)
     ))
   *
 )"""

KEYLIST_SCHEMA = _parseSchema(KEYLIST_TEMPLATE, SCHEMA_TABLE)

MIRRORLIST_TEMPLATE = r"""
 (=mirrorlist
   (=ts .TIME)
   (=mirrors (:anyof
     (=mirror ((:unordered (=name .) (=urlbase .) (=contents (:someof .))
                           .ATTRS)))))
   *)
"""

MIRRORLIST_SCHEMA = _parseSchema(MIRRORLIST_TEMPLATE, SCHEMA_TABLE)

TIMESTAMP_TEMPLATE = r"""
 (=ts
   ((:unordered (=at .TIME) (=m .TIME .) (=k .TIME .)
           (:anyof (=b . . .TIME . .)) .ATTRS))
 )"""

TIMESTAMP_SCHEMA = _parseSchema(TIMESTAMP_TEMPLATE, SCHEMA_TABLE)

BUNDLE_TEMPLATE = r"""
 (=bundle
   (=at .TIME)
   (=os .)
   (:maybe (=arch .))
   (=packages
     (:someof
      (. . . . ((:unordered
                  (:maybe (=order . . .))
                  (:maybe (=optional))
                  (:anyof (=gloss . .))
                  (:anyof (=longgloss . .))
                  .ATTRS)))
     )
   )
   *
 )"""

BUNDLE_SCHEMA = _parseSchema(BUNDLE_TEMPLATE, SCHEMA_TABLE)

PACKAGE_TEMPLATE = r"""
 (=package
  ((:unordered (=name .)
               (=version .)
               (=format . (.ATTRS))
               (=path .)
               (=ts .TIME)
               (=digest .)
               (:anyof (=shortdesc . .))
               (:anyof (=longdesc . .))
               .ATTRS)))
"""

PACKAGE_SCHEMA = _parseSchema(PACKAGE_TEMPLATE, SCHEMA_TABLE)

ALL_ROLES = ('timestamp', 'mirrors', 'bundle', 'package', 'master')

class Key:
    def __init__(self, key, roles):
        self.key = key
        self.roles = []
        for r,p in roles:
            self.addRole(r,p)

    def addRole(self, role, path):
        assert role in ALL_ROLES
        self.roles.append(role, path)

    def getRoles(self):
        return self.rules

    @staticmethod
    def fromSExpression(sexpr):
        # must match PUBKEY_SCHEMA
        typeattr = sexp.access.s_attr(sexpr[1], "type")
        if typeattr == 'rsa':
            key = glider.keys.RSAKey.fromSExpression(sexpr)
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

    def checkSignature(self, method, sexpr=None, digest=None):
        if digest == None:
            _, digest = self.key._digest(sexpr, method)
        ok = self.key.checkSignature(method, digest=digest)
        # XXXX CACHE HERE.
        return ok

class Keystore(KeyDB):
    def __init__(self):
        KeyDB.__init__(self)

    @staticmethod
    def addFromKeylist(sexpr, allowMasterKeys=False):
        # Don't do this until we have validated the structure.
        for ks in sexpr.access.s_lookup_all("keys.key"):
            attrs = ks[1]
            key_s = ks[2]
            roles = s_attr(attrs, "roles")
            #XXXX Use interface of Key, not RSAKey.
            key = Key.fromSExpression(key_s)
            if not key:
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


