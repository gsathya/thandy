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
            version = package['version']

            handles.append(
                ExePackageHandle(self.getDB(),
                                 package['name'],
                                 version,
                                 [],  # filelist not implemented in this.
                                 rp,
                                 self._repo.getFilename(rp),
                                 extra['exe_args']))
        return handles

    def canBeAutomatic(self):
        return True

    def canHaveUI(self):
        return True

class ExePackageHandle(pdb.DBBackedPackageHandle):
    def __init__(self, packageDB, name, version, filelist, relpath, filename,
                 arguments):
        pdb.DBBackedPackageHandle.__init__(packageDB, name, version, filelist)
        self._relPath = relpath
        self._filename = filename
        self._arguments = arguments

    def getRelativePath(self):
        return self._relPath

    def _doInstall(self):
        commandline = [ self._filename ] + self._arguments
        logging.info("Installing %s.  Command line: %s", self._filename,
                     commandLine)
        subprocess.call(commandline)


