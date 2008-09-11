
import OpenSSL.crypto

import sexp.access
import sexp.encode
import time
import re

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

class KeyDB:
    def __init__(self):
        self.keys = {}
    def addKey(self, k):
        self.keys[k.getKeyID()] = k
    def getKey(self, keyid):
        return self.keys[keyid]

def rolePathMatches(rolePath, path):
    """

    >>> rolePath.matches("a/b/c/", "a/b/c/")
    True
    >>> rolePath.matches("**/c.*", "a/b/c.txt")
    True
    """
    rolePath = re.escape(rolePath).replace(r'\*\*', r'.*')
    rolePath = rolePath.replace(r'\*', r'[^/]*')
    rolePath += "$"
    return re.match(rolePath, path) != None

def checkSignatures(signed, keyDB, role, path):
    goodSigs = []
    badSigs = []
    unknownSigs = []
    tangentialSigs = []

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
            result = key.checkSignature(method, data, sig)
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

def sign(signed, key):
    assert sexp.access.s_tag(signed) == 'signed'
    s = signed[1]
    keyid = key.keyID()

    oldsignatures = [ s for s in signed[2:] if s_child(s[1], "keyid") != keyid ]
    signed[2:] = oldsignatures

    for method, sig in key.sign(s):
        signed.append(['signature', [['keyid', keyid], ['method', method]]
                       sig])

def formatTime(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))

def parseTime(s):
    return time.timegm(time.strptime(s, "%Y-%m-%d %H:%M:%S"))


TIME_SCHEMA = r"""/\{d}4-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/"""

ATTRS_SCHEMA = r"""(:anyof (_ *))"""

SIGNED_SCHEMA = r"""
 (=signed
   _
   (:someof
     (=signature ((:unordered
                    (=keyid _) (=method _) .ATTRS)) _)
   )
 )"""

KEYFILE_SCHEMA = r"""
 (=keylist
   (=ts .TIME)
   (=keys
     (:anyof
       (=key ((:unordered (=roles (:someof (. .))) .ATTRS)) _)
     ))
   *
 )"""

MIRRORLIST_SCHEMA = r"""
 (=mirrorlist
   (=ts .TIME)
   (=mirrors (:anyof
     (=mirror ((:unordered (=name .) (=urlbase .) (=contents (:someof .))
                           .ATTRS)))))
   *)
"""

TIMESTAMP_SCHEMA = r"""
 (=ts
   ((:unordered (=at .TIME) (=m .TIME .) (=k .TIME .)
           (:anyof (=b . . .TIME . .)) .ATTRS))
 )"""

BUNDLE_SCHEMA = r"""
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

PACKAGE_SCHEMA = r"""
 (=package
  ((:unordred (=name .)
              (=version .)
              (=format . (.ATTRS))
              (=path .)
              (=ts .TIME)
              (=digest .)
              (:anyof (=shortdesc . .))
              (:anyof (=longdesc . .))
              .ATTRS)))
"""
