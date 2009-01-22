# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import thandy.packagesys.PackageSystem as PS

import os
try:
    import rpm
except ImportError:
    rpm = None
import md5

import thandy.formats

__all__ = [ 'RPMPackageSystem' ]

_CALLBACK_CODES = {}

for name in dir(rpm):
    if name.startswith("RPMCALLBACK_"):
        _CALLBACK_CODES[getattr(rpm, name)] = name[12:]
del name

class RPMPackageTransaction:

   def _start(self):
       PS.PackageTransaction.__init__(self)
       self._tset = rpm.TransactionSet()

   def _commit(self):
       self._tset.run(self._callback, "")
       
   def _callback(self, what, amount, total, mydata, _):
       if what == rpm.RPMCALLBACK_INST_OPEN_FILE:
           hdr, path = mydata
           logging.info("Installing RPM for %s [%s]", hdr['name'], path)

       elif what == rpm.RPMCALLBACK_INST_CLOSE_FILE:
           hdr, path = mydata
           logging.info("Done installing RPM for %s", path)
           
       elif what == rpm.RPMCALLBACK_INST_PROGRESS:
           hdr, path = mydata
           logging.info("%s: %.5s%% done", name, float(amount)/total*100)

       else:
           hdr, path = mydata
           logging.info("RPM event %s on %s [%s/%s]",
                        _CALLBACK_CODES.get(what,str(what)),
                        hdr['name'], amount, total)

def addRPMInstall(ts, path):
    fd = os.open(path, os.O_RDONLY)
    try:
        hdr = ts.hdrFromFdno(fd)
    finally:
        os.close(fd)
    ts.addInstall(hdr, (hdr, path), "u")

def addRPMErase(ts, name):
    ts.addErase(name)

def getInstalledRPMVersions(name, ts=None):
    if ts is None:
        ts = rpm.TransactionSet()
        #XXXX need to close?

    versions = set()
    for match in ts.dbMatch(rpm.RPMTAG_NAME, name):
        versions.add(match['version'])

    return versions

def fileMD5(fname):
    d = md5.new()
    try:
        f = open(fname, 'r')
        try:
            while 1:
                s = f.read(4096)
                if not s:
                    break
                d.update(s)

        finally:
            f.close()
    except OSError, e:
        logging.warn("Couldn't get digest of %s: %s", fname, e)
        return None

    return d.hexdigest()

def checkRPMInstall(name, version, ts=None):
    if ts is None:
        ts = rpm.TransactionSet()
        #XXXX need to close?

    found = False
    all_ok = True

    for h in ts.dbMatch(rpm.RPMTAG_NAME, name):
        if h['version'] != version:
            continue

        found = True

        for fname, flags, md5sum in zip(h['filenames'], h['fileflags'], h['filemd5s']):
            haveMD5 = fileMD5(fname)
            if not haveMD5:
                if (flags & rpm.RPMFILE_MISSINGOK):
                    logging.info("%s is missing or unreadable from %s %s; "
                                 "that's ok.", fname, name, h['version'])
                else:
                    logging.warn("%s is missing or unreadable from %s %s.",
                                 fname, name, h['version'])
                    all_ok = False
            elif haveMD5 == md5sum:
                logging.info("%s is unchanged from %s %s",
                             fname, name, h['version'])
            else:
                # file changed.  If it's not configuration, that's a problem.
                if not (flags & rpm.RPMFILE_CONFIG):
                    logging.warn("%s changed from installed version of %s %s",
                                 fname, name, h['version'])
                    all_ok = False

    return found and all_ok

class RPMChacker(PS.Checker):
    def __init__(self, rpmname, rpmversion):
        PS.Checker.__init__(self)
        self._name = rpmname
        self._version = rpmversion

    def __repr__(self):
        return "RPMChecker(%r, %r)"%(self._name, self._version)

    def getInstalledVersions(self):
        return getInstalledRPMVersions(self._name, self._transaction)

    def isInstalled(self):
        vers = getInstalledRPMVersions(self._name, self._transaction)
        return self._version in vers

#    def checkInstall(self):
#        return checkRPMInstall(self._name, self._version)

class RPMInstaller(PS.Installer):
    def __init__(self, rpmname, relPath):
        PS.Installer.__init__(self, relPath)
        self._name = rpmname

    def __repr__(self):
        return "RPMInstaller(%r, %r)"%(self._name, self._relPath)

    def install(self, transaction):
        addRPMInstall(transaction._trans, self.getFilename())

    def remove(self, transaction):
        addRPMErase(transaction._trans, self._name)

