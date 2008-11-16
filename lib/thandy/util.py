# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import os
import sys
import tempfile
import random

try:
    import json
except ImportError:
    import simplejson as json

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

def ensureParentDir(name):
    """DOCDOC"""
    directory = os.path.split(name)[0]
    if not os.path.exists(directory):
        os.makedirs(directory, 0700)

def getKeylist(keys_fname, checkKeys=True):
    import thandy.master_keys

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
