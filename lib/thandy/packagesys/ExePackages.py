# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import thandy.packagesys.PackageSystem as ps
import thandy.packagesys.PackageDB as pdb

class ExePackageSystem(pdb.DBBackedPackageSystem):

    def getName(self):
        return "executable"

    def packageHandleFromJSON(self, json):
        raise NotImplemented()  #XXXX????

    def canBeAutomatic(self):
        return True

    def canHaveUI(self):
        return True

class ExePackageHandle(pdb.DBBackedPackageHandle):
    def __init__(self, packageDB, name, version, filelist, filename,
                 arguments):
        pdb.DBBackedPackageHandle.__init__(packageDB, name, version, filelist)
        self._filename = filename
        self._arguments = arguments

    def _doInstall(self):
        commandline = [ self._filename ] + self._arguments
        logging.info("Installing %s.  Command line: %s", self._filename,
                     commandLine)
        subprocess.call(commandline)


