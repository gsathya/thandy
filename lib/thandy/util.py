# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import logging
import os
import re
import sys
import tempfile
import random

try:
    import _winreg
except ImportError:
    _winreg = None

import thandy.formats
import thandy.keys
import thandy.master_keys

_jsonModule = None

def importJSON():
    global _jsonModule
    if _jsonModule is not None:
        return _jsonModule

    for name in [ "json", "simplejson" ]:
        try:
            mod = __import__(name)
        except ImportError:
            continue
        if not hasattr(mod, "dumps"):
            # Some versions of Ubuntu have a module called 'json' that is
            # not a recognizable simplejson module.  Naughty.
            if name == 'json':
                logging.warn("Your operating system has a nonfunctional json "
                             "module.  That's going to break any programs that "
                             "use the real json module in Python 2.6.  Trying "
                             "simplejson instead.")
            continue

        # Some old versions of simplejson escape / as \/ in a misguided and
        # inadequate attempt to fix XSS attacks.  Make them not do that.  This
        # code is not guaranteed to work on all broken versions of simplejson:
        # it replaces an entry in the internal character-replacement
        # dictionary so that "/" is translated to itself rather than to \/.
        # We also need to make sure that ensure_ascii is False, so that we
        # do not call the C-optimized string encoder in these broken versions,
        # which we can't fix easily.  Both parts are a kludge.
        try:
            escape_dct = mod.encoder.ESCAPE_DCT
        except NameError:
            pass
        else:
            if escape_dct.has_key("/"):
                escape_dct["/"] = "/"
                save_dumps = mod.dumps
                save_dump = mod.dump
                def dumps(*k, **v):
                    v['ensure_ascii']=False
                    return save_dumps(*k,**v)
                def dump(*k,**v):
                    v['ensure_ascii']=False
                    return save_dump(*k,**v)
                mod.dump = dump
                mod.dumps = dumps
                logging.warn("Your operating system has an old broken "
                             "simplejson module.  I tried to fix it for you.")

        _jsonModule = mod
        return mod

    raise ImportError("Couldn't import a working json module")

json = importJSON()

def moveFile(fromLocation, toLocation):
    """Move the file from fromLocation to toLocation, removing any file
       in toLocation.
    """
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
    """Return a path relative to $THANDY_HOME or ~/.thandy whose final path
       component is 'name', creating parent directories as needed."""
    try:
        base = os.environ["THANDY_HOME"]
    except KeyError:
        base = "~/.thandy"

    base = os.path.expanduser(base)
    result = os.path.normpath(os.path.join(base, name))
    ensureParentDir(result)
    return result

def ensureParentDir(name):
    """If the parent directory of 'name' does not exist, create it."""
    directory = os.path.split(name)[0]
    if not os.path.exists(directory):
        os.makedirs(directory, 0700)

def getKeylist(keys_fname, checkKeys=True):
    """Return a Keylist() containing all the keys in master_keys, plus
       all the keys in $THANDY_HOME.preload_keys, plus all the keys stored
       in keys_fname.  If check_keys, exclude from keys_fname any keys not
       signed by enough master keys.  Do not allow master keys to occur in
       keys_fname."""
    keydb = thandy.formats.Keylist()

    for key in thandy.master_keys.MASTER_KEYS:
        keydb.addKey(thandy.keys.RSAKey.fromJSon(key))

    user_keys = userFilename("preload_keys")
    if os.path.exists(user_keys):
        #XXXX somewhat roundabout.
        keylist = thandy.formats.makeKeylistObj(user_keys)
        keydb.addFromKeylist(keylist, allowMasterKeys=True)

    if keys_fname and os.path.exists(keys_fname):
        f = open(keys_fname, 'r')
        try:
            obj = json.load(f)
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

def randChooseWeighted(lst):
    """Given a list of (weight,item) tuples, pick an item with
       probability proportional to its weight.
    """

    totalweight = sum(w for w,i in lst)
    position = random.uniform(0, totalweight)
    soFar = 0

    # We could use bisect here, but this is not going to be in the
    # critical path.  If it is, oops.
    for w,i in lst:
        soFar += w
        if position < soFar:
            return i

    return lst[-1][1]

class NoRegistry(thandy.Exception):
    """Exception raised when we try to access the registry on a
       non-win32 machine."""
    pass

def getRegistryValue(keyname):
    """Read the contents of a Windows registry key from a given base."""
    if _winreg is None:
        raise NoRegistry()

    hkey, rest = keyname.split("\\", 1)
    key, value = rest.rsplit("\\", 1)
    if not hkey.startswith("HKEY_"):
        return None

    base = getattr(_winreg, hkey)
    settings = None

    try:
        try:
            settings = _winreg.OpenKey(base, key)
            return _winreg.QueryValueEx(settings, value)[0]
        except (WindowsError, ValueError, TypeError):
            return None
    finally:
        if settings is not None:
            settings.Close()

_controlLog = logging.getLogger("thandy-ctrl")

def formatLogString(s):
    s = '"%s"' % re.sub(r'(["\\])', r'\\\1', s)
    s = s.replace("\n", "\\n")
    return s

def logCtrl(key, **args):
    """DOCDOC"""
    parts = [ key ]
    parts.extend(
        "%s=%s"%(k, formatLogString(v)) for k,v in sorted(args.iteritems()))
    _controlLog.log(logging.INFO, " ".join(parts))

