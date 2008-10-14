# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import urllib2
import httplib
import random

import threading, Queue

import thandy.util

class Downloads:
    def __init__(self, n_threads=2):
        self._lock = threading.RLock()
        self.downloads = {}
        self.haveDownloaded = {}
        self.downloadQueue = Queue.Queue()
        self.threads = [ threading.Thread(target=self._thread) ]
        for t in self.threads:
            t.setDaemon(True)

    def start(self):
        for t in self.threads:
            t.start()

    def isCurrentlyDownloading(self, relPath):
        self._lock.acquire()
        try:
            return self.downloads.has_key(relPath)
        finally:
            self._lock.release()

    def isRedundant(self, relPath):
        self._lock.acquire()
        try:
            return (self.downloads.has_key(relPath) or
                    self.haveDownloaded.has_key(relPath))
        finally:
            self._lock.release()

    def addDownloadJob(self, job):
        rp = job.getRelativePath()
        self._lock.acquire()
        self.downloads[rp] = job
        self._lock.release()
        self.downloadQueue.put(job)

    def _thread(self):
        while True:
            job = self.downloadQueue.get()
            job.download()
            rp = job.getRelativePath()
            self._lock.acquire()
            try:
                del self.downloads[rp]
                self.haveDownloaded[rp] = True
            finally:
                self._lock.release()

class DownloadJob:
    def __init__(self, relPath, destPath, mirrorlist=None,
                 wantHash=None, canStall=False):
        self._relPath = relPath
        self._wantHash = wantHash
        self._mirrorList = mirrorlist
        self._destPath = destPath

        tmppath = thandy.util.userFilename("tmp")
        if relPath.startswith("/"):
            relPath = relPath[1:]
        self._tmppath = os.path.join(tmppath, relPath)

        d = os.path.dirname(self._tmppath)
        if not os.path.exists(d):
            os.makedirs(d, 0700)

    def getRelativePath(self):
        return self._relPath

    def haveStalledFile(self):
        return os.path.exists(self._tmppath)

    def getURL(self, mirrorlist=None):
        if mirrorlist is None:
            mirrorlist = self._mirrorList
        weightSoFar = 0
        usable = []

        for m in mirrorlist['mirrors']:
            for c in m['contents']:
                # CHECK FOR URL SUITABILITY XXXXX

                if thandy.formats.rolePathMatches(c, self._relPath):
                    weightSoFar += m['weight']
                    usable.append( (weightSoFar, m) )
                    break

        wTarget = random.randint(0, weightSoFar)
        mirror = None
        # Could use bisect here instead
        for w, m in mirrorlist:
            if w >= wTarget:
                mirror = m
                break

        return m['urlbase'] + self._relPath

    def download(self):
        # XXXX RESUME

        f_in = urllib2.urlopen(self.getURL())
        f_out = open(self._tmpPath, 'w')
        while True:
            c = f_in.read(1024)
            if not c:
                break
            f_out.write(c)
        f_in.close()
        f_out.close()
        # XXXXX retry on failure

        if self._wantHash:
            gotHash = thandy.formats.getFileDigest(self._tmpPath)
            if gotHash != self._wantHash:
                # XXXX Corrupt file.
                pass

        thandy.utils.moveFile(self._tmpPath, self._destPath)
