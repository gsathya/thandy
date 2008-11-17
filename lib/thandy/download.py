# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import httplib
import logging
import os
import Queue
import random
import sys
import threading
import traceback
import urllib2

import thandy.util
import thandy.socksurls


class DownloadManager:
    """Class to track a set of downloads and pass them out to worker threads.
    """
    def __init__(self, n_threads=2):
        # Prevents concurrent modification to downloads and haveDownloaded
        self._lock = threading.RLock()
        # Map from resource relPath to job.
        self.downloads = {}
        # Map from resource relPath from True to objects that we have
        # managed to dowload.
        self.haveDownloaded = {}
        # Work queue of DownloadJobs that we intend to process once a thread
        # is free.
        self.downloadQueue = Queue.Queue()
        # DOCDOC
        self.resultQueue = Queue.Queue()

        # List of worker threads.
        self.threads = [ threading.Thread(target=self._thread, args=[idx])
                         for idx in xrange(n_threads) ]
        # Condition that gets triggered whenever a thread is finished doing
        # something.
        self.done = threading.Condition()
        for t in self.threads:
            t.setDaemon(True)

    def start(self):
        """Start all of this download manager's worker threads."""
        for t in self.threads:
            t.start()

    def isCurrentlyDownloading(self, relPath):
        """Return true iff this download manager is currently downloading
           some copy of the resource at relPath."""
        self._lock.acquire()
        try:
            return self.downloads.has_key(relPath)
        finally:
            self._lock.release()

    def isRedundant(self, relPath):
        """Return true iff we are currently downloading, or have
           downloaded, the resource at relPath."""

        self._lock.acquire()
        try:
            return (self.downloads.has_key(relPath) or
                    self.haveDownloaded.has_key(relPath))
        finally:
            self._lock.release()

    def finished(self):
        """Return true iff we have no active or pending jobs."""
        self._lock.acquire()
        try:
            return self.downloadQueue.empty() and len(self.downloads) == 0
        finally:
            self._lock.release()

    def wait(self):
        """Pause until we have no active or pending jobs."""
        while not self.finished():
            self.done.acquire()
            self.done.wait()
            self.done.release()

            try:
                while True:
                    item = self.resultQueue.get(block=False)
                    item()
            except Queue.Empty:
                pass

    def addDownloadJob(self, job):
        """Add another DownloadJob to the end of the work queue."""
        rp = job.getRelativePath()
        self._lock.acquire()
        self.downloads[rp] = job
        self._lock.release()
        self.downloadQueue.put(job)

    def downloadFailed(self, mirror, relpath):
        """DOCDOC"""
        pass # Track failure; don't try the same mirror right away.

    def _thread(self, idx):
        # Run in the background per thread.  idx is the number of the thread.
        while True:
            job = self.downloadQueue.get() # Grab job from queue.
            rp = job.getRelativePath()
            success = False
            try:
                logging.info("start %s in Thread %s", rp, idx)
                success = job.download() # Execute the download.
                logging.info("end %s in Thread %s", rp, idx)
            finally:
                self._lock.acquire()
                try:
                    del self.downloads[rp]
                    if success: # If we downloaded correctly, say so.
                        self.haveDownloaded[rp] = True
                finally:
                    self._lock.release()

                if success:
                    self.resultQueue.put(job._success)
                else:
                    self.resultQueue.put(job._failure)

                self.done.acquire()
                self.done.notify()
                self.done.release()

class DownloadJob:
    """Abstract base class.  Represents a thing to be downloaded, and the
       knowledge of how to download it."""
    def __init__(self, targetPath, tmpPath, wantHash=None, repoFile=None,
                 useTor=False):
        """Create a new DownloadJob.  When it is finally downloaded,
           store it in targetPath.  Store partial results in tmpPath;
           if there is already a file in tmpPath, assume that it is an
           incomplete download. If wantHash, reject the file unless
           the hash is as given.  If useTor, use a socks connection."""
        #DOCDODC repofile
        self._destPath = targetPath
        self._tmpPath = tmpPath
        self._wantHash = wantHash
        self._repoFile = repoFile
        self._useTor = useTor

        self._success = lambda : None
        self._failure = lambda : None

    def setCallbacks(self, success, failure):
        """DOCDOC"""
        self._success = success
        self._failure = failure

    def getURL(self):
        """Abstract implementation helper.  Returns the URL that the
           _download function downloads from."""
        raise NotImplemented()

    def getRelativePath(self):
        """Abstract. Returns a string representing this download, to
           keep two downloads of the same object from running at once.
           In Thandy, this is usually a relative path of a downloaded
           object within the repository.
        """
        raise NotImplemented()

    def haveStalledFile(self):
        """Return true iff we have an existing incomplete download stored in
           the temporary file.
        """
        return os.path.exists(self._tmpPath)

    def download(self):
        """Main interface function: Start the download, and return
           when complete.
        """
        try:
            self._download()
            return True
        except (OSError, httplib.error, urllib2.HTTPError,
                thandy.DownloadError), err:
            # XXXXX retry on failure
            logging.warn("Download failed: %s", err)
            return False
        except:
            tp, val, tb = sys.exc_info()
            logging.warn("Internal during download: %s, %s", val,
                         traceback.format_exc())
            return False

    def _download(self):
        # Implementation function.  Unlike download(), can throw exceptions.
        f_in = f_out = None

        try:
            url = self.getURL()

            logging.info("Downloading %s", url)

            if self.haveStalledFile():
                have_length = os.stat(self._tmpPath).st_size
                logging.info("Have stalled file for %s with %s bytes", url,
                             have_length)
            else:
                have_length = None

            f_in = getConnection(url, self._useTor, have_length)

            logging.info("Connected to %s", url)

            gotRange = f_in.info().get("Content-Range")
            expectLength = f_in.info().get("Content-Length", "???")
            if gotRange:
                if gotRange.startswith("bytes %s-"%(have_length+1)):
                    logging.info("Resuming download from %s"%url)
                    f_out = open(self._tmpPath, 'a')
                else:
                    raise thandy.DownloadError("Got an unexpected range %s"
                                               %gotRange)
            else:
                f_out = open(self._tmpPath, 'w')

            total = 0
            while True:
                c = f_in.read(1024)
                if not c:
                    break
                f_out.write(c)
                total += len(c)
                logging.debug("Got %s/%s bytes from %s",
                              total, expectLength, url)

        finally:
            if f_in is not None:
                f_in.close()
            if f_out is not None:
                f_out.close()

        if self._wantHash and not self._repoFile:
            gotHash = thandy.formats.getFileDigest(self._tmpPath)
            if gotHash != self._wantHash:
                raise thandy.DownloadError("File hash was not as expected.")
        elif self._repoFile:
            self._repoFile.checkFile(self._tmpPath, self._wantHash)

        thandy.util.ensureParentDir(self._destPath)
        thandy.util.moveFile(self._tmpPath, self._destPath)


class SimpleDownloadJob(DownloadJob):
    """Testing subtype of DownloadJob: just downloads a URL and writes it to
       disk."""
    def __init__(self, targetPath, url,
                 wantHash=None, supportedURLTypes=None, useTor=False):
        DownloadJob.__init__(self, targetPath, targetPath+".tmp",
                                 wantHash=wantHash,
                                 useTor=useTor)
        self._url = url

    def getURL(self):
        return self._url

    def getRelativePath(self):
        return self._url

class ThandyDownloadJob(DownloadJob):
    """Thandy's subtype of DownloadJob: knows about mirrors, weighting,
       and Thandy's directory structure."""
    def __init__(self, relPath, destPath, mirrorList, wantHash=None,
                 supportedURLTypes=None, useTor=None, repoFile=None):

        DownloadJob.__init__(self, destPath, None, wantHash=wantHash,
                             useTor=useTor, repoFile=repoFile)
        self._mirrorList = mirrorList
        self._relPath = relPath

        tmppath = thandy.util.userFilename("tmp")
        if relPath.startswith("/"):
            relPath = relPath[1:]
        self._tmpPath = os.path.join(tmppath, relPath)

        d = os.path.dirname(self._tmpPath)
        if not os.path.exists(d):
            os.makedirs(d, 0700)

        self._supportedURLTypes = None
        if self._supportedURLTypes is None and useTor:
            self._supportedURLTypes = [ "http", "https" ]


    def getURL(self):
        usable = []

        for m in self._mirrorList['mirrors']:
            for c in m['contents']:

                if self._supportedURLTypes is not None:
                    urltype = urllib2.splittype(m['urlbase'])[0]
                    if urltype.lower() not in self._supportedURLTypes:
                        continue

                if thandy.formats.rolePathMatches(c, self._relPath):
                    usable.append( (m['weight'], m) )
                    break

        mirror = thandy.util.randChooseWeighted(usable)

        if m['urlbase'][-1] == '/' and self._relPath[0] == '/':
            return m['urlbase'] + self._relPath[1:]
        else:
            return m['urlbase'] + self._relPath

    def getRelativePath(self):
        return self._relPath


_socks_opener = thandy.socksurls.build_socks_opener()

def getConnection(url, useTor, have_length=None):
    """Open a connection to 'url'.  We already have received
       have_length bytes of the file we're trying to fetch, so resume
       if possible.

    """
    headers = {}
    urltype = urllib2.splittype(url)[0]
    is_http = urltype in ["http", "https"]

    if have_length is not None and is_http:
        headers['Range'] = "bytes=%s-"%(have_length+1)

    req = urllib2.Request(url, headers=headers)

    if useTor:
        conn = _socks_opener.open(req)
    else:
        conn = urllib2.urlopen(req)

    return conn


if __name__ == '__main__':
    # Trivial CLI to test out downloading.

    import getopt
    options, args = getopt.getopt(sys.argv[1:], "",
                                  ["use-tor", "socksport=", "threads="])

    useTor = False
    socksPort = 9050
    nThreads = 2
    for o,v in options:
        if o == "--use-tor":
            useTor = True
        elif o == "--socksport":
            socksPort = int(v)
        elif o == "--threads":
            nThreads = int(v)

    logging.basicConfig(level=logging.DEBUG)

    if useTor:
        thandy.socksurls.setSocksProxy("127.0.0.1", socksPort)

    manager = DownloadManager(nThreads)

    for url in args:
        fn = urllib2.splithost(urllib2.splittype(url)[1])[1]
        fn = os.path.split(fn)[1]

        job = SimpleDownloadJob(fn, url, useTor=useTor)
        manager.addDownloadJob(job)

    manager.start()
    manager.wait()
