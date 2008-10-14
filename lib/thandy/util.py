
import os
import sys
import tempfile

import simplejson

import thandy.formats
import thandy.keys
import thandy.master_keys

def moveFile(fromLocation, toLocation):
    if sys.platform in ('cygwin', 'win32'):
        # Win32 doesn't let rename replace an existing file.
        try:
            os.unlink(toLocation)
        except OSError:
            pass
    os.rename(fromLocation, toLocation)


def replaceFile(fname, contents, textMode=False):
    """overwrite the file in 'fname' atomically with the content of 'contents'
    """
    dir, prefix = os.path.split(fname)
    fd, fname_tmp = tempfile.mkstemp(prefix=prefix, dir=dir, text=textMode)

    try:
        os.write(fd, contents)
    finally:
        os.close(fd)

    moveFile(fname_tmp, fname)

def userFilename(name):
    try:
        base = os.environ["THANDY_HOME"]
    except KeyError:
        base = "~/.thandy"
    base = os.path.expanduser(base)
    if not os.path.exists(base):
        os.makedirs(base, 0700)
    return os.path.join(base, name)

def getKeylist(keys_fname, checkKeys=True):
    import thandy.master_keys

    keydb = thandy.formats.Keylist()

    for key in thandy.master_keys.MASTER_KEYS:
        keydb.addKey(key)

    user_keys = userFilename("preload_keys")
    if os.path.exists(user_keys):
        #XXXX somewhat roundabout.
        keylist = thandy.formats.makeKeylistObj(user_keys)
        keydb.addFromKeylist(keylist, allowMasterKeys=True)

    if keys_fname and os.path.exists(keys_fname):
        f = open(keys_fname, 'r')
        try:
            obj = simplejson.load(f)
        finally:
            f.close()
        ss, role, path = thandy.formats.checkSignedObj(obj, keydb)
        if role != 'master':
            raise thandy.FormatException("%s wasn't a keylist."%keys_fname)
        if checkKeys and not ss.isValid():
            raise thandy.FormatException("%s not signed by enough master keys"%
                                         keys_fname)
        keydb.addFromKeylist(obj['signed'], allowMasterKeys=False)

    return keydb
