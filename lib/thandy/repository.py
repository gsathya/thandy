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

MAX_TIMESTAMP_AGE = 24*60*60

class RepositoryFile:
    def __init__(self, repository, relativePath, schema,
                 needRole=None, signedFormat=True, needSigs=1):
        self._repository = repository
        self._relativePath = relativePath
        self._schema = schema
        self._needRole = needRole
        self._signedFormat = signedFormat
        self._needSigs = needSigs

        self._signed_obj = self._main_obj = None
        self._sigStatus = None
        self._mtime = None

    def getRelativePath(self):
        return self._relativePath

    def getPath(self):
        return self._repository.getFilename(self._relativePath)

    def _load(self):
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
        if content == None:
            content = sexpr.encode

        signed_obj,main_obj = self._checkContent(content)

        fname = self.getPath()
        thandy.util.replaceFile(fname, contents)

        self._signed_obj = signed_obj
        self._main_obj = main_obj
        self._mtime = mtime

    def _checkContent(self, content):

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

    def load(self):
        if self._main_obj == None:
            self._load()

    def get(self):
        return self._main_obj

    def isLoaded(self):
        return self._main_obj != None

    def getContent(self):
        self.load()
        return self._main_obj

    def _checkSignatures(self):
        self.load()
        sigStatus = thandy.formats.checkSignatures(self._signed_obj,
                                     self._repository._keyDB,
                                     self._needRole, self._relativePath)
        self._sigStatus = sigStatus

    def checkSignatures(self):
        if self._sigStatus is None:
            self._checkSignatures()
        return self._sigStatus

class LocalRepository:
    def __init__(self, root):
        self._root = root
        self._keyDB = thandy.util.getKeylist(None)

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

        self._packageFiles = {}
        self._bundleFiles = {}

    def getFilename(self, relativePath):
        if relativePath.startswith("/"):
            relativePath = relativePath[1:]
        return os.path.join(self._root, relativePath)

    def getKeylistFile(self):
        return self._keylistFile

    def getTimestampFile(self):
        return self._timestampFile

    def getMirrorlistFile(self):
        return self._mirrorlistFile

    def getPackageFile(self, relPath):
        try:
            return self._packageFiles[relPath]
        except KeyError:
            self._packageFiles[relPath] = pkg = RepositoryFile(
                self, relPath, thandy.formats.PACKAGE_SCHEMA,
                needRole='package')
            return pkg

    def getBundleFile(self, relPath):
        try:
            return self._bundleFiles[relPath]
        except KeyError:
            self._bundleFiles[relPath] = pkg = RepositoryFile(
                self, relPath, thandy.formats.BUNDLE_SCHEMA,
                needRole='bundle')
            return pkg

    def getFilesToUpdate(self, now=None, trackingBundles=()):
        if now == None:
            now = time.time()

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
            ts = thandy.formats.TimestampFile.fromJSon(ts)
            if age > MAX_TIMESTAMP_AGE:
                need.add(self._timestampFile.getRelativePath())

        # If the keylist isn't signed right, we can't check the
        # signatures on anything else.
        if self._keylistFile.get():
            s = self._keylistFile.checkSignatures()
            if not s.isValid(): # For now only require one master key.
                need.add(self._keylistFile.getRelativePath())

        if need:
            return need

        # Import the keys from the keylist.
        self._keyDB.addFromKeylist(self._keylistFile.get())

        # If the timestamp isn't signed right, get a new timestamp and a
        # new keylist.
        s = self._timestampFile.checkSignatures()
        if not s.isValid():
            need.add(self._keylistFile.getRelativePath())
            need.add(self._timestampFile.getRelativePath())
            return need

        # FINALLY, we know we have an up-to-date, signed timestamp
        # file.  Check whether the keys and mirrors file are as
        # authenticated.
        h_kf = thandy.formats.getDigest(self._keylistFile.get())
        h_expected = ts.getKeylistInfo().getHash()
        if h_kf != h_expected:
            need.add(self._keylistFile.getRelativePath())

        if need:
            return need

        s = self._mirrorlistFile.checkSignatures()
        if not s.isValid():
            need.add(self._mirrorlistFile.getRelativePath())

        h_mf = thandy.formats.getDigest(self._mirrorlistFile.get())
        h_expected = ts.getMirrorlistInfo().getHash()
        if h_mf != h_expected:
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
                logging.warn("Unrecognized bundle %s"%b)
                continue

            rp = binfo.getRelativePath()
            bfile = self.getBundleFile(rp)
            try:
                bfile.load()
            except OSError:
                need.add(rp)
                continue

            h_b = thandy.formats.getDigest(bfile.get())
            h_expected = binfo.getHash()
            if h_b != h_expected:
                need.add(rp)
                continue

            s = bfile.checkSignatures()
            if not s.isValid():
                # Can't actually use it.
                continue

            bundles[rp] = bfile

        # Okay.  So we have some bundles.  See if we have their packages.
        packages = {}
        for bfile in bundles.values():
            bundle = bfile.get()
            for pkginfo in bundle['packages']:
                rp = pkginfo['path']
                pfile = self.getPackageFile(rp)
                try:
                    pfile.load()
                except OSError:
                    need.add(rp)
                    continue

                h_p = thandy.formats.getDigest(pfile.get())
                h_expected = thandy.formats.parseHash(pkginfo['hash'])
                if h_p != h_expected:
                    need.add(rp)
                    continue

                s = pfile.checkSignatures()
                if not s.isValid():
                    # Can't use it.
                    continue
                packages[rp] = pfile

        # Finally, we have some packages.  Do we have their underlying
        # files?
        for pfile in packages.values():
            package = pfile.get()
            for f in package['files']:
                rp, h = f[:2]
                h_expected = thandy.formats.parseHash(h)
                fn = self.getFilename(rp)
                try:
                    h_got = thandy.formats.getFileDigest(fn)
                except OSError:
                    need.add(rp)
                    continue
                if h_got != h_expected:
                    need.add(rp)

        # Okay; these are the files we need.
        return need
