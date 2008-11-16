# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import anydbm
import shelve

import thandy.util
import thandy.formats

class SimplePackageDB:

    def __init__(self, filename):
        self._db = anydbm.open(filename, 'c')

    def setVersion(self, package, version, filelist):
        pass

    def setInstallParameters(self, package, params):
        pass

    def getCurVersion(self, package):
        pass

    def getInstallParameters(self, package):
        pass


class DBBackedPackageSystem(thandy.packagesys.PackageSystem):
    def __init__(self, packageDB):
        self._packageDB = packageDB

class DBBackedPackageHandle(thandy.packagesys.PackageHandle):
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
        return self._packageDB.getCurVersion(self._name) != None

    def getInstalledVersion(self, transaction=None):
        return self._packageDB.getCurVersion(self._name)

    def install(self):
        params = self._doInstall()
        self._packageDB.setCurVersion(
            self._name, self._version, self._filelist)
        self._packageDB.setInstallParameters(self._name, params)

    def _doInstall(self):
        raise NotImplemented()

    def isInstalled(self):
        return self.getInstalledVersion(self, transaction) == self._version

    def checkInstall(self):
        base = self._getInstallBase()

        all_ok = True
        for fn, hash in self._filelist:
            fn = os.path.join(base, fn)
            if not os.path.exists(fn):
                all_ok = False
            else:
                f = open(fn, 'rb')
                try:
                    try:
                        d = thandy.formats.getFileDigest(f)
                    except OSError:
                        all_ok = False
                        break
                finally:
                    f.close()

        return all_ok
