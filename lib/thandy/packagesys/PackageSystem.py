# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

class PackageMetasystem:
    def __init__(self, repository):
        self._repostitory = repository
        self._systems = {}

    def addPackageSystem(self, system):
        self._systems[system.getName()] = system

    def getSysForPackage(self, pkg):
        return self._systems.get(pkg['format'], None)

    @staticmethod
    def create(repository):
        r = PackageMetasystem(repository)

        try:
            import rpm
        except ImportError:
            pass
        else:
            import thandy.packagesys.RPMPackages
            r.addPackageSystem(thandy.packagesys.RPMPackages.RPMPackageSystem(
                    repository))

        import thandy.packagesys.ExePackages
        r.addPackageSystem(thandy.packagesys.ExePackages.ExePackageSystem(
                repository))

        return r

class PackageSystem:
    def getName(self):
        raise NotImplemented()

    def packageHandlesFromJSON(self, json):
        raise NotImplemented()

    def canBeAutomatic(self):
        return True

    def canHaveUI(self):
        return False

    def getTransaction(self):
        return PackageTransaction()

class PackageTransaction:
    def __init__(self):
        self._transactions = []

    def _start(self):
        pass

    def _commit(self):
        pass

    def run(self):
        self._start()
        for cb in self._transactions:
            cb(self)
        self._commit()

    def addInstall(self, packageHandle):
        self._transactions.append(packageHandle.install)

    def addRemove(self, packageHandle):
        self._transactions.append(packageHandle.remove)

class PackageHandle:
    def __init__(self):
        pass

    def getRelativePath(self):
        raise NotImplemented()

    def isInstalled(self, transaction=None):
        raise NotImplemented()

    def anyVersionInstalled(self, transaction=None):
        raise NotImplemented()

    def getInstalledVersion(self, transaction=None):
        raise NotImplemented()

    def install(self, transaction):
        raise NotImplemented()

    def remove(self, transaction):
        raise NotImplemented()

    def checkInstall(self, transaction=None):
        raise NotImplemented()
