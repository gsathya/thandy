# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import thandy.formats
import thandy.util

try:
    import json
except ImportError:
    import simplejson as json

import logging
import os
import threading
import time

MAX_TIMESTAMP_AGE = 3*60*60

class RepositoryFile:
    """Represents information about a file stored in our local repository
       cache.  Used to validate and load files.
    """
    def __init__(self, repository, relativePath, schema,
                 needRole=None, signedFormat=True, needSigs=1):
        """Allocate a new RepositoryFile for a file to be stored under
           the LocalRepository 'repository' in relativePath.  Make
           sure the file validates with 'schema' (or its signed form,
           if 'signedFormat').  When checking signatures, this file needs
           at least 'needSigs' signatures with role 'needRole'.
        """
        # These fields are as in the arguments.
        self._repository = repository
        self._relativePath = relativePath
        self._schema = schema
        self._needRole = needRole
        self._signedFormat = signedFormat
        self._needSigs = needSigs

        # The contents of the file, parsed.  None if we haven't loaded
        # the file.
        self._main_obj = None

        # The contents of the file along with their signatures.  May
        # be aliased by _main_obj.  None if we haven't loaded the
        # file.
        self._signed_obj = None

        # A SignatureStatus object, if we have checked signatures.
        self._sigStatus = None
        # The mtime of the file on disk, if we know it.
        self._mtime = None

    def clear(self):
        """DOCDOC"""
        self._main_obj = self._signed_obj = None
        self._sigStatus = None
        self._mtime = None

    def getRelativePath(self):
        """Return the filename for this item relative to the top of the
           repository."""
        return self._relativePath

    def getPath(self):
        """Return the actual filename for this item."""
        return self._repository.getFilename(self._relativePath)

    def _load(self):
        """Helper: load and parse this item's contents."""
        fname = self.getPath()

        # Propagate OSError
        f = None
        fd = os.open(fname, os.O_RDONLY)
        try:
            f = os.fdopen(fd, 'r')
        except:
            os.close(fd)
            raise
        try:
            mtime = os.fstat(fd).st_mtime
            content = f.read()
        finally:
            f.close()

        signed_obj,main_obj = self._checkContent(content)

        self._signed_obj = signed_obj
        self._main_obj = main_obj
        self._mtime = mtime

    def _save(self, content=None):
        """Helper: Flush this object's contents to disk."""
        if content == None:
            content = sexpr.encode

        signed_obj,main_obj = self._checkContent(content)

        fname = self.getPath()
        thandy.util.replaceFile(fname, contents)

        self._signed_obj = signed_obj
        self._main_obj = main_obj
        self._mtime = time.time()

    def _checkContent(self, content):
        """Helper.  Check whether 'content' matches SIGNED_SCHEMA, and
           self._schema (as appropraite).  Return a tuple of the
           signed_schema match, and the schema match, or raise
           FormatException."""

        try:
            obj = json.loads(content)
        except ValueError, e:
            raise thandy.FormatException("Couldn't decode content: %s"%e)

        if self._signedFormat:
            # This is supposed to be signed.
            thandy.formats.SIGNED_SCHEMA.checkMatch(obj)

            main_obj = obj['signed']
            signed_obj = obj
        else:
            signed_obj = None
            main_obj = obj

        if self._schema != None:
            self._schema.checkMatch(main_obj)

        return signed_obj, main_obj

    def checkFile(self, fname, needhash=None):
        f = open(fname, 'r')
        try:
            s = f.read()
        finally:
            f.close()

        signed, main = self._checkContent(s)
        if needhash:
            d = thandy.formats.getDigest(main)
            if d != needhash:
                raise thandy.FormatException("Content didn't match needed "
                                             "hash.")

    def load(self):
        """Load this object from disk if it hasn't already been loaded."""
        if self._main_obj == None:
            self._load()

    def get(self):
        """Return the object, or None if it isn't loaded."""
        return self._main_obj

    def isLoaded(self):
        """Return true iff this object is loaded."""
        return self._main_obj != None

    def getContent(self):
        """Load this object as needed and return its content."""
        self.load()
        return self._main_obj

    def _checkSignatures(self):
        """Helper: Try to verify all the signatures on this object, and
           cache the SignatureStatus object."""
        self.load()
        sigStatus = thandy.formats.checkSignatures(self._signed_obj,
                                     self._repository._keyDB,
                                     self._needRole, self._relativePath)
        self._sigStatus = sigStatus

    def checkSignatures(self):
        """Try to verify all the signatures on this object if we
           haven't already done so, and return a SignatureStatus
           object."""
        if self._sigStatus is None:
            self._checkSignatures()
        return self._sigStatus

class PkgFile:
    def __init__(self, repository, relativePath, needHash):
        self._repository = repository
        self._relativePath = relativePath
        self._needHash = needHash

        self._mtime = None

    def clear(self):
        self._mtime = None

    def load(self):
        pass

    def getRelativePath(self):
        return self._relativePath

    def getPath(self):
        fname = self._repository.getFilename(self._relativePath)
        return os.path.normpath(fname)

    def getExpectedHash(self):
        return self._needHash

    def checkFile(self, fname, needHash=None):
        if needHash:
            if thandy.formats.getFileDigest(fname) != needHash:
                raise thandy.FormatException("Digest for %s not as expected.")

class LocalRepository:
    """Represents a client's partial copy of a remote mirrored repository."""
    def __init__(self, root):
        """Create a new local repository that stores its files under 'root'"""
        # Top of our mirror.
        self._root = root

        # A base keylist of master keys; we'll add others later.
        self._keyDB = thandy.util.getKeylist(None)

        # Entries for the three invariant metafiles.
        self._keylistFile = RepositoryFile(
            self, "/meta/keys.txt", thandy.formats.KEYLIST_SCHEMA,
            needRole="master")
        self._timestampFile = RepositoryFile(
            self, "/meta/timestamp.txt", thandy.formats.TIMESTAMP_SCHEMA,
            needRole="timestamp")
        self._mirrorlistFile = RepositoryFile(
            self, "/meta/mirrors.txt", thandy.formats.MIRRORLIST_SCHEMA,
            needRole="mirrors")

        self._metaFiles = [ self._keylistFile,
                            self._timestampFile,
                            self._mirrorlistFile ]

        # Map from relative path to a RepositoryFile for packages.
        self._packageFiles = {}

        # Map from relative path to a RepositoryFile for bundles.
        self._bundleFiles = {}

    def getFilename(self, relativePath):
        """Return the file on disk that caches 'relativePath'."""
        if relativePath.startswith("/"):
            relativePath = relativePath[1:]
        return os.path.join(self._root, relativePath)

    def getKeylistFile(self):
        """Return a RepositoryFile for our keylist."""
        return self._keylistFile

    def getTimestampFile(self):
        """Return a RepositoryFile for our timestamp file."""
        return self._timestampFile

    def getMirrorlistFile(self):
        """Return a RepositoryFile for our mirrorlist."""
        return self._mirrorlistFile

    def getPackageFile(self, relPath):
        """Return a RepositoryFile for a package stored at relative path
           'relPath'."""
        try:
            return self._packageFiles[relPath]
        except KeyError:
            self._packageFiles[relPath] = pkg = RepositoryFile(
                self, relPath, thandy.formats.PACKAGE_SCHEMA,
                needRole='package')
            return pkg

    def getBundleFile(self, relPath):
        """Return a RepositoryFile for a bundle stored at relative path
           'relPath'."""
        try:
            return self._bundleFiles[relPath]
        except KeyError:
            self._bundleFiles[relPath] = pkg = RepositoryFile(
                self, relPath, thandy.formats.BUNDLE_SCHEMA,
                needRole='bundle')
            return pkg

    def getRequestedFile(self, relPath, pkgSystems=None):
        """DOCDOC"""
        for f in self._metaFiles:
            if f.getRelativePath() == relPath:
                return f
        for f in self._bundleFiles.itervalues():
            if f.getRelativePath() == relPath:
                return f
        for f in self._packageFiles.itervalues():
            if f.getRelativePath() == relPath:
                return f
            f.load()
            for item in f.get()['files']:
                rp, h = item[:2]
                if rp == relPath:
                    return PkgFile(self, rp, thandy.formats.parseHash(h))

        return None

    def getFilesToUpdate(self, now=None, trackingBundles=(), hashDict=None,
                         pkgSystems=None, installableDict=None):
        """Return a set of relative paths for all files that we need
           to fetch.  Assumes that we care about the bundles
           'trackingBundles'.
           DOCDOC pkgSystems, installableDict, hashDict
        """

        if now == None:
            now = time.time()

        if hashDict == None:
            # Use a dummy hashdict.
            hashDict = {}

        if installableDict == None:
            installableDict = {}

        need = set()

        # Fetch missing metafiles.
        for f in self._metaFiles:
            try:
                f.load()
            except OSError, e:
                print "need", f.getPath()
                logging.info("Couldn't load %s: %s.  Must fetch it.",
                             f.getPath(), e)
                need.add(f.getRelativePath())

        # If the timestamp file is out of date, we need to fetch it no
        # matter what.  (Even if it is isn't signed, it can't possibly
        # be good.)
        ts = self._timestampFile.get()
        if ts:
            age = now - thandy.formats.parseTime(ts['at'])
            if age > MAX_TIMESTAMP_AGE:
                logging.info("Timestamp file from %s is out of "
                             "date; must fetch it.", ts['at'])
                need.add(self._timestampFile.getRelativePath())

            ts = thandy.formats.TimestampFile.fromJSon(ts)

        # If the keylist isn't signed right, we can't check the
        # signatures on anything else.
        if self._keylistFile.get():
            s = self._keylistFile.checkSignatures()
            if not s.isValid(): # For now only require one master key.
                logging.info("Key list is not properly signed; must get a "
                             "new one.")
                need.add(self._keylistFile.getRelativePath())

        if need:
            return need

        # Import the keys from the keylist.
        self._keyDB.addFromKeylist(self._keylistFile.get())

        # If the timestamp isn't signed right, get a new timestamp and a
        # new keylist.
        s = self._timestampFile.checkSignatures()
        if not s.isValid():
            logging.info("Timestamp file is not properly signed; fetching new "
                         "timestamp file and keylist.")
            need.add(self._keylistFile.getRelativePath())
            need.add(self._timestampFile.getRelativePath())
            return need

        # FINALLY, we know we have an up-to-date, signed timestamp
        # file.  Check whether the keys and mirrors file are as
        # authenticated.
        hashDict[self._keylistFile.getRelativePath()] = \
            ts.getKeylistInfo().getHash()
        hashDict[self._mirrorlistFile.getRelativePath()] = \
            ts.getMirrorlistInfo().getHash()

        h_kf = thandy.formats.getDigest(self._keylistFile.get())
        h_expected = ts.getKeylistInfo().getHash()
        if h_kf != h_expected:
            logging.info("Keylist file hash did not match.  Must fetch it.")
            need.add(self._keylistFile.getRelativePath())

        if need:
            return need

        s = self._mirrorlistFile.checkSignatures()
        if not s.isValid():
            logging.info("Mirrorlist file signatures not valid. Must fetch.")
            need.add(self._mirrorlistFile.getRelativePath())

        h_mf = thandy.formats.getDigest(self._mirrorlistFile.get())
        h_expected = ts.getMirrorlistInfo().getHash()
        if h_mf != h_expected:
            logging.info("Mirrorlist file hash did not match. Must fetch.")
            need.add(self._mirrorlistFile.getRelativePath())

        if need:
            return need

        # Okay; that's it for the metadata.  Do we have the right
        # bundles?
        bundles = {}
        for b in trackingBundles:
            try:
                binfo = ts.getBundleInfo(b)
            except KeyError:
                logging.warn("Bundle %s not listed in timestamp file."%b)
                continue

            rp = binfo.getRelativePath()
            h_expected = binfo.getHash()
            hashDict[rp] = h_expected
            bfile = self.getBundleFile(rp)
            try:
                bfile.load()
            except OSError:
                logging.info("Can't find bundle %s on disk; must fetch.", rp)
                need.add(rp)
                continue

            h_b = thandy.formats.getDigest(bfile.get())
            if h_b != h_expected:
                logging.info("Bundle hash for %s not as expected; must fetch.",
                             rp)
                need.add(rp)
                continue

            s = bfile.checkSignatures()
            if not s.isValid():
                # Can't actually use it.
                logging.warn("Bundle hash was as expected, but signatures did "
                             "not match.")
                continue

            bundles[rp] = bfile

        # Okay.  So we have some bundles.  See if we have their packages.
        packages = {}
        for bfile in bundles.values():
            bundle = bfile.get()
            for pkginfo in bundle['packages']:
                rp = pkginfo['path']
                pfile = self.getPackageFile(rp)
                h_expected = thandy.formats.parseHash(pkginfo['hash'])
                hashDict[rp] = h_expected
                try:
                    pfile.load()
                except OSError:
                    logging.info("Can't find package %s on disk; must fetch.",
                                 rp)
                    need.add(rp)
                    continue

                h_p = thandy.formats.getDigest(pfile.get())
                if h_p != h_expected:
                    logging.info("Wrong hash for package %s; must fetch.", rp)
                    need.add(rp)
                    continue

                s = pfile.checkSignatures()
                if not s.isValid():
                    logging.warn("Package hash was as expected, but signature "
                                 "did nto match")
                    # Can't use it.
                    continue
                packages[rp] = pfile

        # Finally, we have some packages.  Do we have their underlying
        # files?
        for pfile in packages.values():
            package = pfile.get()

            alreadyInstalled = {}
            allHandles = {}
            if pkgSystems is not None:
                psys = pkgSystems.getSysForPackage(package)
                if psys is None:
                    logging.info("No way to check whether a %s package is "
                                 "up-to-date." % package['format'])
                else:
                    handles = psys.packageHandlesFromJSON(package)

                    for h in handles:
                        allHandles[h.getRelativePath()] = h
                        if h.isInstalled():
                            alreadyInstalled[h.getRelativePath()] = h

            pkg_rp = pfile.getRelativePath()

            for f in package['files']:
                rp, h = f[:2]
                if alreadyInstalled.has_key(rp):
                    logging.info("%s is already installed; no need to download",
                                 rp)
                    continue

                h_expected = thandy.formats.parseHash(h)
                hashDict[rp] = h_expected
                fn = self.getFilename(rp)
                try:
                    h_got = thandy.formats.getFileDigest(fn)
                except (OSError, IOError):
                    logging.info("Installable file %s not found on disk; "
                                 "must load", rp)
                    need.add(rp)
                    continue
                if h_got != h_expected:
                    logging.info("Hash for %s not as expected; must load.", rp)
                    need.add(rp)
                else:
                    if allHandles.has_key(rp):
                        installableDict.setdefault(pkg_rp, {})[rp] = allHandles[rp]

        # Okay; these are the files we need.
        return need
