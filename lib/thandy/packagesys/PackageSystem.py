# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import os

def getItemsFromPackage(pkg):
    result = {}
    format = pkg.get('format')
    for item in pkg['files']:
        relPath = item[0]
        if len(item) >= 3:
            extra = item[2]
        else:
            extra = {}
        checkFormat = extra.get("check_type")
        installFormat = extra.get("install_type")

        checker = getChecker(checkFormat, relPath, extra, defaultFormat=format,
                             package=pkg)
        installer = getInstaller(installFormat, relPath, extra,
                                 defaultFormat=format, package=pkg)
        result[relPath] = PackageItem(relPath, checker, installer)
    return result

def getChecker(checkType, relPath, extra, defaultFormat, package):
    if checkType == None:
        #DOCDOC obsolete
        if defaultFormat == 'rpm':
            import thandy.packagesys.RPMPackages
            return thandy.packagesys.RPMPackages.RPMChecker(
                os.path.split(relPath)[1],
                extra['rpm_version'])
        elif defaultFormat == 'exe':
            if extra.has_key('registry_ent'):
                import thandy.packagesys.ExePackages
                k,v=extra['registry_ent']
                return thandy.packagesys.ExePackages.RegistryChecker(k, v)
            else:
                import thandy.packagesys.PackageDB
                return thandy.packagesys.PackageDB.DBChecker(
                    package['name'], package['version'])
        else:
            return None
    elif checkType == 'rpm':
        import thandy.packagesys.RPMPackages
        return thandy.packagesys.RPMPackages.RPMChecker(
            os.path.split(relPath)[1],
            extra['rpm_version'])
    elif checkType == 'db':
        import thandy.packagesys.PackageDB
        return thandy.packagesys.PackageDB.DBChecker(
            extra['item_name'], extra['item_version'])
    elif checkType == 'registry':
        import thandy.packagesys.ExePackages
        k,v=extra['registry_ent']
        return thandy.packagesys.ExePackages.RegistryChecker(k,v)
    else:
        return None

def getInstaller(installType, relPath, extra, defaultFormat, package):
    if installType == None:
        # XXX obsolete.
        if defaultFormat == 'rpm':
            import thandy.packagesys.RPMPackages
            return thandy.packagesys.RPMPackages.RPMInstaller(
                relPath, os.path.split(relPath)[1])
        elif defaultFormat == 'exe':
            import thandy.packagesys.ExePackages
            installer = thandy.packagesys.ExePackages.CommandInstaller(
                relPath, [ "${FILE}" ] + extra.get('exe_args', []))
            if not extra.has_key('registry_ent'):
                import thandy.packagesys.PackageDB
                installer = thandy.packagesys.PackageDB.DBInstaller(
                    package['name'], package['version'], relPath, installer)
            return installer
        else:
            return None
    elif installType == 'rpm':
        import thandy.packagesys.RPMPackages
        installer = thandy.packagesys.RPMPackages.RPMInstaller(
            relPath, os.path.split(relPath)[1])
    elif installType == 'command':
        import thandy.packagesys.ExePackages
        installer = thandy.packagesys.ExePackages.CommandInstaller(
            relPath, extra['cmd_install'], extra['cmd_remove'])
    else:
        return None

    if extra.get('check_type') == 'db':
        import thandy.packagesys.PackageDB
        installer = thandy.packagesys.PackageDB.DBInstaller(
            extra['item_name'], extra['item_version'], installer)

    return installer

class PackageItem:
    def __init__(self, relativePath, checker, installer):
        self._relPath = relativePath
        self._checker = checker
        self._installer = installer

    def setTransaction(self, transaction):
        if self._cheker is not None:
            self._checker.setTransaction(transaction)
        if self._installer is not None:
            self._installer.setTransaction(transaction)
    def setCacheRoot(self, cacheRoot):
        if self._installer is not None:
            self._installer.setCacheRoot(cacheRoot)

    def canCheck(self):
        return self._checker != None
    def canInstall(self):
        return self._installer != None
    def getChecker(self):
        return self._checker
    def getInstaller(self):
        return self._installer

class Checker:
    def __init__(self):
        self._transaction = None

    def setTransaction(self, transaction):
        self._transaction = transaction

#    def checkInstall(self):
#        raise NotImplemented()

    def anyVersionInstalled(self):
        raise len(self.getInstalledVersions()) > 1

    def getInstalledVersions(self):
        raise NotImplemented()

    def isInstalled(self):
        raise NotImplemented()

class Installer:
    def __init__(self, relativePath):
        self._transaction = None
        self._cacheRoot = None
        self._relPath = relativePath

    def setTransaction(self, transaction):
        self._transaction = transaction

    def setCacheRoot(self, cacheRoot):
        self._cacheRoot = cacheRoot

    def getFilename(self):
        rp = self._relPath
        if rp.startswith('/'):
            rp = rp[1:]
        return os.path.normpath(os.path.join(self._cacheRoot, rp))

    def install(self, relativePath, root):
        raise NotImplemented()

    def remove(self):
        raise NotImplemented()

    def getInstallResult(self):
        "DOCDOC params, manifest"
        return None, None


