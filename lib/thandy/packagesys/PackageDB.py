# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import anydbm
import atexit
import shelve

import thandy.util
import thandy.formats

import thandy.packagesys.PackageSystem

class SimplePackageDB:
    def __init__(self, filename):
        thandy.util.ensureParentDir(filename)
        self._db = anydbm.open(filename, 'c')
        atexit.register(self.close)

    def close(self):
        self._db.close()

    def setVersion(self, package, version, filelist):
        self._db['pv_%s'%str(package)] = (version, filelist)

    def setInstallParameters(self, package, params):
        self._db['ip_%s'%str(package)] = params

    def getCurVersion(self, package):
        v = self._db.get('pv_%s'%str(package))
        if v != None:
            return v[0]

    def getInstallParameters(self, package):
        return self._db.get('pi_%s'%str(package))

class DBBackedPackageSystem(thandy.packagesys.PackageSystem.PackageSystem):
    def __init__(self):
        self._packageDB = None

    def getDB(self):
        if self._packageDB is None:
            fname = thandy.util.userFilename("db/packages")
            self._packageDB = SimplePackageDB(fname)
        return self._packageDB

class DBBackedPackageHandle(thandy.packagesys.PackageSystem.PackageHandle):
    def __init__(self, packageDB, name, version, filelist):
        thandy.packagesys.PackageSystem.PackageHandle.__init__(self)
        self._packageDB = packageDB
        self._name = name
        self._version = version
        self._filelist = filelist

        self._metaData = None

    def _getInstallBase(self):
        raise NotImplemented()

    def anyVersionInstalled(self, transaction=None):
        return self.getInstalledVersion(transaction) != None

    def getInstalledVersion(self, transaction=None):
        return self._packageDB.getCurVersion(self._name)

    def install(self, transaction=None):
        params = self._doInstall()
        self._packageDB.setCurVersion(
            self._name, self._version, self._filelist)
        self._packageDB.setInstallParameters(self._name, params)

    def _doInstall(self):
        raise NotImplemented()

    def isInstalled(self, transaction=None):
        return self.getInstalledVersion(transaction) == self._version

    def checkInstall(self, transaction=None):
        base = self._getInstallBase()

        all_ok = True
        for fn, hash in self._filelist:
            fn = os.path.join(base, fn)
            if not os.path.exists(fn):
                all_ok = False
            else:
                try:
                    d = thandy.formats.getFileDigest(fn)
                    if d != hash:
                        all_ok = False
                except OSError:
                    all_ok = False
                    break


        return all_ok
