# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import atexit
import shelve
import logging

import thandy.util
import thandy.formats

import thandy.packagesys.PackageSystem as PS

class SimplePackageDB:
    """Trivial wrapper around Python's shelve module to provide storage for
       installation information for package items that don't automatically
       record their presence.
    """
    def __init__(self, filename):
        thandy.util.ensureParentDir(filename)
        self._db = shelve.open(filename, 'c')
        atexit.register(self.close)

    def close(self):
        self._db.close()

    def setVersion(self, package, version, filelist):
        self._db['pv_%s'%str(package)] = (version, filelist)

    def setInstallParameters(self, package, params):
        self._db['ip_%s'%str(package)] = params

    def setManifest(self, package, fnameToDigest):
        self._db['mf_%s'%str(package)] = fnameToDigest

    def getCurVersion(self, package):
        v = self._db.get('pv_%s'%str(package))
        if v != None:
            return v[0]
        else:
            return None

    def getInstallParameters(self, package):
        return self._db.get('pi_%s'%str(package))

    def getManifest(self, package):
        return self._db.get('mf_%s'%str(package), {})

    def removeAll(self, package):
        for template in ["pv_%s", "ip_%s", "mf_%s"]:
            try:
                del self._db[template % str(package)]
            except KeyError:
                pass

_DB_INSTANCE = None

def getPackageDBInstance():
    global _DB_INSTANCE
    if _DB_INSTANCE == None:
        fname = thandy.util.userFilename("db/packages")
        logging.info("Opening package database in %s", fname)
        _DB_INSTANCE = SimplePackageDB(fname)
    return _DB_INSTANCE

class _DBMixin:
    def setDB(self, db):
        self._db = db

    def getDB(self):
        if self._db is None:
            self._db = getPackageDBInstance()
        return self._db

class DBChecker(PS.Checker, _DBMixin):
    def __init__(self, name, version):
        PS.Checker.__init__(self)
        self._name = name
        self._version = version
        self._db = None

    def __repr__(self):
        return "DBChecker(%r, %r)"%(self._name, self._version)

#    def checkInstall(self):
#        if not self.isInstalled():
#            return False
#        else:
#            return self._checkManifest()
#
#    def _getInstallRoot(self):
#        return "/"
#
#    def _checkManifest(self):
#        manifest = self.getDB().getManifest(self._name)
#        root = self._getInstallRoot()
#        all_ok = True
#        for fname, digest_want in manifest:
#            real_fname = os.path.join(self._getInstallRoot(), fname)
#            logging.info("Checking digest on %s", fname)
#            try:
#                digest = thandy.formats.getFileDigest(real_fname):
#                if digest != digest_want:
#                    logging.warn("Digest on %s not as expected", real_fname)
#                    all_ok = False
#            except OSError:
#                logging.warn("File %s not found.", real_fname)
#                all_ok = False
#        return all_ok
#
    def getInstalledVersions(self):
        return [ self.getDB().getCurVersion(self._name) ]

    def isInstalled(self):
        return self._version in self.getInstalledVersions()

class DBInstaller(PS.Installer, _DBMixin):
    def __init__(self, name, version, relPath, installer):
        PS.Installer.__init__(self, relPath)
        self._name = name
        self._version = version
        self._installer = installer

    def __repr__(self):
        return "DBInstaller(%r, %r, %r, %r)"%(self._name,
                                              self._version,
                                              self._relPath,
                                              self._installer)

    def setTransaction(self, transaction):
        self._installer.setTransaction(transaction)

    def setCacheRoot(self, cacheRoot):
        self._installer.setCacheRoot(cacheRoot)

    def install(self):
        self._installer.install()

        params, manifest = self._installer.getInstallResult()
        self.getDB().setCurVersion(self._name, self._version)
        if params != None:
            self.getDB().getInstallParameters(self._name, params)
        if manifest != None:
            self.getDB().setManifest(self._name, manifest)

    def remove(self):
        self._installer.remove()
        self.getDB().removeAll(self._name)


