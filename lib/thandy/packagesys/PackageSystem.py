# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

class PackageSystem:
    def getName(self):
        raise NotImplemented()

    def packageHandleFromJSON(self, json):
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
