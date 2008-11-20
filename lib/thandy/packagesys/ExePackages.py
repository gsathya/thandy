# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import subprocess

import thandy.util
import thandy.packagesys.PackageSystem as ps
import thandy.packagesys.PackageDB as pdb

class ExePackageSystem(pdb.DBBackedPackageSystem):
    def __init__(self, repo):
        self._repo = repo

    def getName(self):
        return "exe"

    def packageHandlesFromJSON(self, pkg):
        if pkg['format'] != 'exe':
            raise thandy.FormatException()

        handles = []
        for entry in pkg['files']:
            if len(entry) < 3:
                continue
            rp, h, extra = entry[:3]
            version = pkg['version']

            handles.append(
                ExePackageHandle(self.getDB(),
                                 pkg['name'],
                                 version,
                                 [],  # filelist not implemented in this.
                                 rp,
                                 self._repo.getFilename(rp),
                                 arguments=extra['exe_args'],
                                 registry_ent=extra.get('registry_ent')))
        return handles

    def canBeAutomatic(self):
        return True

    def canHaveUI(self):
        return True

class ExePackageHandle(pdb.DBBackedPackageHandle):
    def __init__(self, packageDB, name, version, filelist, relpath, filename,
                 arguments, registry_ent=None):
        pdb.DBBackedPackageHandle.__init__(packageDB, name, version, filelist)
        self._relPath = relpath
        self._filename = filename
        self._arguments = arguments
        self._registry_ent = registry_ent

    def getRelativePath(self):
        return self._relPath

    def getInstalledVersion(self, transaction=None):
        if self._registry_ent != None:
            ver = thandy.util.getRegistryValue(self._registry_ent[0])
            if ver != None:
                return ver
        else:
            return pdb.DBBackedPackageHandle.getInstalledVersion(self, transaction)

    def isInstalled(self, transaction=None):
        if self._registry_ent != None:
            ver = thandy.util.getRegistryValue(self._registry_ent[0])
            if ver == self._registry_ent[1]:
                return True
        else:
            return pdb.DBBackedPackageHandle.isInstalled(self, transaction)


    def _doInstall(self):
        commandline = [ self._filename ] + self._arguments
        logging.info("Installing %s.  Command line: %s", self._filename,
                     commandLine)
        subprocess.call(commandline)

