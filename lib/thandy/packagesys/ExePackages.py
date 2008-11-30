# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import subprocess
import logging
import re
import os

import thandy.util
import thandy.packagesys.PackageSystem as PS
import thandy.packagesys.PackageDB as PDB

class RegistryChecker(PS.Checker):
    def __init__(self, key, version):
        PS.Checker.__init__(self)
        self._key = key
        self._version = version

    def __repr__(self):
        return "RegistryChecker(%r, %r)"%(self._key, self._version)

    def getInstalledVersions(self):
        try:
            return [ thandy.util.getRegistryValue(self._key) ]
        except thandy.util.NoRegistry:
            raise thandy.CheckNotSupported("This OS has no registry.")

    def isInstalled(self):
        return self._version in self.getInstalledVersions()

class CommandInstaller(PS.Installer):
    def __init__(self, relPath, installCommand, removeCommand=None):
        PS.Installer.__init__(self, relPath)
        self._installCommand = installCommand
        self._removeCommand = removeCommand

    def __repr__(self):
        parts = [ "CommandInstaller(%r, %r" %(self._relPath,
                                              self._installCommand) ]
        if self.removeCommand:
            parts.append(", %r"%self.removeCommand)
        parts.append(")")
        return "".join(parts)

    def install(self):
        self._runCommand(self._installCommand)

    def remove(self):
        if self._removeCommand:
            raise thandy.RemoveNotSupported()
        self._runCommand(self._removeCommand)

    def _runCommand(self, command):
        d = { "FILE": self.getFilename() }
        def replace(m):
            return d[m.group(1)]
        try:
            c = [ re.sub(r'\$\{([\w_]+)\}', replace, word) for word in command ]
        except KeyError:
            raise thandy.InstallFailed("Unrecognized option in command %s"
                                       %command)
        logging.info("Installing %s.  Command is %s", self._relPath, c)

        return_code = self._execute(c)
        if return_code != 0:
            raise thandy.InstallFailed("Return code %s from calling %s"%
                                       (return_code, c))

    def _execute(self, cmd):
        try:
            return subprocess.call(cmd)
        except OSError, e:
            logging.warn("Error from trying to call %s: %s", cmd, e)
            raise thandy.InstallFailed("Could not execute install command %s"
                                       %cmd)


