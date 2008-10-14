
import os
import getopt
import sys
import logging
import simplejson

import thandy.keys
import thandy.formats

def getKeyStore():
    return thandy.keys.KeyStore(thandy.util.userFilename("secret_keys"))

def dumpKey(key, indent=0):
    i = " "*indent
    print "%s%s"%(i, key.getKeyID())
    for r, p in key.getRoles():
        print "  %s%s\t%s"%(i, r, p)

def getKey(ks, keyid=None, role=None, path=None):
    if keyid is not None:
        keys = ks.getKeysFuzzy(keyid)
        if None not in (role, path):
            keys = [ k for k in keys if k.hasRole(role, path) ]
    elif None not in (role, path):
        keys = ks.getKeysByRole(role, path)
    else:
        assert False
    if len(keys) < 1:
        print "No such key.\nI wanted",
        if keyid: print "keyid='%s...'"%keyid,
        if None not in (role, path): print "role=%s, path=%s"%(role,path),
        print
        print "I only know about:"
        for k in ks.iterkeys():
            dumpKey(k)
        sys.exit(1)
    elif len(keys) > 1:
        print "Multiple keys match.  Possibilities are:"
        for k in keys:
            dumpKey(k)
        sys.exit(1)
    else:
        return keys[0]

# ------------------------------

def makepackage(args):
    options, args = getopt.getopt(args, "", "keyid=")
    keyid = None
    for o,v in options:
        if o == "--keyid":
            keyid = v

    if len(args) < 2:
        usage()

    configFile = args[0]
    dataFile = args[1]
    print "Generating package."
    package = thandy.formats.makePackageObj(configFile, dataFile)
    relpath = package['location']
    print "need a key with role matching [package %s]"%relpath
    ks = getKeyStore()
    ks.load()
    key = getKey(ks, keyid=keyid, role='package', path=relpath)
    signable = thandy.formats.makeSignable(package)
    thandy.formats.sign(signable, key)

    if 1:
        ss, r, p = thandy.formats.checkSignedObj(signable, ks)
        assert ss.isValid()

    location = os.path.split(package['location'])[-1]
    print "Writing signed package to %s"%location
    f = open(location, 'w')
    simplejson.dump(signable, f, indent=1)
    f.close()

def makebundle(args):
    options, args = getopt.getopt(args, "", "keyid=")
    keyid = None
    for o,v in options:
        if o == "--keyid":
            keyid = v

    if len(args) < 2:
        usage()

    configFile = args[0]
    packages = {}
    for pkgFile in args[1:]:
        print "Loading", pkgFile
        f = open(pkgFile, 'r')
        p = simplejson.load(f)
        f.close()
        _, r, _ = thandy.formats.checkSignedObj(p)
        if r != 'package':
            print pkgFile, "was not a package"
        packages[p['signed']['location']] = p

    def getHash(path):
        p = packages[path]
        return thandy.formats.getDigest(p['signed'])

    bundleObj = thandy.formats.makeBundleObj(configFile, getHash)
    signable = thandy.formats.makeSignable(bundleObj)

    ks = getKeyStore()
    ks.load()
    key = getKey(ks, keyid=keyid, role="bundle", path=bundleObj['location'])
    thandy.formats.sign(signable, key)

    if 1:
        ss, r, p = thandy.formats.checkSignedObj(signable, ks)
        assert ss.isValid()

    location = os.path.split(bundleObj['location'])[-1]
    print "Writing signed bundle to %s"%location
    f = open(location, 'w')
    simplejson.dump(signable, f, indent=1)
    f.close()

# ------------------------------
def makekeylist(args):
    options, args = getopt.getopt(args, "", "keyid=")
    keyid = None
    for o,v in options:
        if o == "--keyid":
            keyid = v

    if len(args) < 1:
        usage()

    keylist = thandy.formats.makeKeylistObj(args[0])
    signable = thandy.formats.makeSignable(keylist)

    ks = getKeyStore()
    ks.load()
    key = getKey(ks, keyid=keyid, role="master", path="/meta/keys.txt")
    thandy.formats.sign(signable, key)

    if 1:
        ss, r, p = thandy.formats.checkSignedObj(signable, ks)
        assert ss.isValid()

    print "writing signed keylist to keys.txt"
    thandy.util.replaceFile("keys.txt",
              simplejson.dumps(signable, indent=1, sort_keys=True),
              textMode=True)

def signkeylist(args):
    if len(args) != 1:
        usage()

    keylist = simplejson.load(open(args[0], 'r'))
    thandy.formats.SIGNED_SCHEMA.checkMatch(keylist)
    thandy.formats.KEYLIST_SCHEMA.checkMatch(keylist['signed'])

    ks = getKeyStore()
    ks.load()
    keys = ks.getKeysByRole("master", "/meta/keys.txt")
    for k in keys:
        thandy.formats.sign(keylist, k)

    print "writing signed keylist to keys.txt"
    thandy.util.replaceFile("keys.txt",
              simplejson.dumps(keylist, indent=1, sort_keys=True),
              textMode=True)

def makemirrorlist(args):
    options, args = getopt.getopt(args, "", "keyid=")
    keyid = None
    for o,v in options:
        if o == "--keyid":
            keyid = v

    if len(args) < 1:
        usage()

    mirrorlist = thandy.formats.makeMirrorListObj(args[0])
    signable = thandy.formats.makeSignable(mirrorlist)

    ks = getKeyStore()
    ks.load()
    key = getKey(ks, keyid=keyid, role='mirrors', path="/meta/mirrors.txt")
    thandy.formats.sign(signable, key)

    if 1:
        ss, r, p = thandy.formats.checkSignedObj(signable, ks)
        assert ss.isValid()

    print "writing signed mirrorlist to mirrors.txt"
    thandy.util.replaceFile("mirrors.txt",
              simplejson.dumps(signable, indent=1, sort_keys=True),
              textMode=True)

# ------------------------------

def keygen(args):
    k = getKeyStore()
    k.load()
    print "Generating key. This will be slow."
    key = thandy.keys.RSAKey.generate()
    print "Generated new key: %s" % key.getKeyID()
    k.addKey(key)
    k.save()

def listkeys(args):
    k = getKeyStore()
    k.load()
    for k in k.iterkeys():
        print k.getKeyID()
        for r, p in k.getRoles():
            print " ", r, p

def addrole(args):
    if len(args) < 3:
        usage()
    ks = getKeyStore()
    ks.load()
    k = getKey(ks, args[0])
    r = args[1]
    if r not in thandy.formats.ALL_ROLES:
        print "Unrecognized role %r.  Known roles are %s"%(
            r,", ".join(thandy.format.ALL_ROLES))
        sys.exit(1)
    p = args[2]
    k.addRole(r, p)
    ks.save()

def delrole(args):
    if len(args) < 3:
        usage()
    ks = getKeyStore()
    ks.load()
    k = getKey(ks, args[0])
    r = args[1]
    if r not in thandy.formats.ALL_ROLES:
        print "Unrecognized role %r.  Known roles are %s"%(
            r,", ".join(thandy.format.ALL_ROLES))
        sys.exit(1)
    p = args[2]

    #XXXX rep.
    origLen = len(k._roles)
    k._roles = [ (role,path) for role,path in k._roles
                 if (role,path) != (r,p) ]
    removed = origLen - len(k._roles)
    print removed, "roles removed"
    if removed:
        ks.save()

def chpass(args):
    ks = getKeyStore()
    print "Old password."
    ks.load()
    print "New password."
    ks.clearPassword()
    ks.save()

def dumpkey(args):
    options, args = getopt.getopt(args, "", ["include-secret", "passwd="])

    includeSecret = False
    for o,v in options:
        if o == '--include-secret':
            includeSecret = True
        else:
            print "Unexpected %r"%o

    ks = getKeyStore()
    ks.load()

    keys = []
    if len(args):
        keys = [ getKey(ks, a) for a in args ]
    else:
        keys = list(ks.iterkeys())

    for k in keys:
        data = k.format(private=includeSecret, includeRoles=True)
        print "Key(", simplejson.dumps(data, indent=2), ")"

def usage():
    print "Known commands:"
    print "  keygen"
    print "  listkeys"
    print "  chpass"
    print "  addrole keyid role path"
    print "  delrole keyid role path"
    print "  dumpkey [--include-secret] keyid"
    print "  makepackage config datafile"
    print "  makebundle config packagefile ..."
    print "  signkeylist keylist"
    print "  makekeylist keylist"
    print "  makemirrorlist config"
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        usage()
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd in [ "keygen", "listkeys", "addrole", "delrole", "chpass",
                "dumpkey", "makepackage", "makebundle", "signkeylist",
                "makekeylist", "signkeylist", "makemirrorlist", ]:
        globals()[cmd](args)
    else:
        usage()

if __name__ == '__main__':
    main()
