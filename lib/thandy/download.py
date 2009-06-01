# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import httplib
import logging
import os
import Queue
import sys
import threading
import time
import urllib2

import thandy.util
import thandy.socksurls
import thandy.checkJson

class BadCompoundData(thandy.DownloadError):
    """DOCDOC"""
    pass

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

        # DOCDOC
        self.statusLog = DownloadStatusLog()

        #DOCDOC
        self._raiseMe = None

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

            if self._raiseMe:
                raise self._raiseMe

            try:
                while True:
                    item = self.resultQueue.get(block=False)
                    item()
            except Queue.Empty:
                pass

    def addDownloadJob(self, job):
        """Add another DownloadJob to the end of the work queue."""
        job.setDownloadStatusLog(self.statusLog)
        rp = job.getRelativePath()
        self._lock.acquire()
        self.downloads[rp] = job
        self._lock.release()
        self.downloadQueue.put(job)

    def getRetryTime(self, mirrorList, relPath):
        """Given a mirrorlist and a filename relative to the repository root,
           return the next time at which we are willing to retry fetching
           that file from any mirror, or 0 if we are willing to try immediately.
        """
        readyAt = None
        for m in mirrorsThatSupport(mirrorList, relPath):
            r = self.statusLog.getDelayTime(m['urlbase'])
            if readyAt == None or r < readyAt:
                readyAt = r
        if readyAt != None:
            return readyAt
        else:
            return 0

    def downloadFailed(self, mirror, relpath):
        """Callback: invoked when a download fails."""
        pass

    def _thread(self, idx):
        # Run in the background per thread.  idx is the number of the thread.
        while True:
            job = self.downloadQueue.get() # Grab job from queue.
            rp = job.getRelativePath()
            success = False
            try:
                logging.info("start %s in Thread %s", rp, idx)
                failure = job.download() # Execute the download.
                logging.info("end %s in Thread %s", rp, idx)
            finally:
                self._lock.acquire()
                try:
                    del self.downloads[rp]
                    if success: # If we downloaded correctly, say so.
                        self.haveDownloaded[rp] = True
                finally:
                    self._lock.release()

                if failure == None:
                    self.statusLog.succeeded(job.getMirror(),
                                             job.getRelativePath())
                    self.resultQueue.put(job._success)
                else:
                    self.statusLog.failed(failure)
                    self.resultQueue.put(job._failure)

                self.done.acquire()
                self.done.notify()
                self.done.release()

class DownloadFailure:
    """Helper class: represents a failure to download an item from a
       mirror.

       Broadly speaking, these errors are possible:

       A - The whole internet is down for us, either because our network
           connection sucks, our proxy is down, or whatever.
         - A particular mirror is down or nonfunctional.

           For these, use DownloadFailure.connectionFailed(): we can't
           easily tell a mirror failure from a network failure when we
           have only a single mirror to look at.

       B - The mirror is giving us errors we don't understand.
         - A particular mirror is missing a file we need.
         - A particular mirror served us something that was allegedly a
           file we need, but that file was no good.

           For these, use DownloadFailure.mirrorFailed(): Whether the
           mirror is broken or we're misunderstanding it, don't try
           to use it for a while.

       C - We finished a partial download and it was no good, but we
           can't tell who was at fault, because we don't know which
           part was corrupt.

           Use DownloadFailure.badCompoundFile().  We don't know who
           to blame, so we treat the whole network as having gone bibbledy.
    """
    def __init__(self, urlbase, relPath, networkError=False):
        self._urlbase = urlbase
        self._relPath = relPath
        self._network = networkError

        self._when = time.time()

    @staticmethod
    def badCompoundFile(relpath):
        return DownloadFailure(None, relpath)

    @staticmethod
    def mirrorFailed(urlbase, relpath):
        return DownloadFailure(urlbase, relpath)

    @staticmethod
    def connectionFailed(urlbase):
        return DownloadFailure(urlbase, None, True)

S = thandy.checkJson
_FAIL_SCHEMA = S.Struct([S.Int(), thandy.formats.TIME_SCHEMA], allowMore=True)
_STATUS_LOG_SCHEMA = S.Obj(
    v=S.Int(),
    mirrorFailures=S.DictOf(S.AnyStr(), _FAIL_SCHEMA),
    networkFailures=_FAIL_SCHEMA)
del S


class DownloadStatusLog:
    """Tracks when we can retry downloading from various mirrors.

       Currently, we treat every failure as affecting a mirror, the
       network, or both.  When a mirror or the network fails, we back
       off for a while before we attempt it again.  For each failure
       with no intervening success, we back off longer.
    """
    # XXXX get smarter.
    # XXXX make this persistent.
    def __init__(self, mirrorFailures={}, networkFailures=[0,0]):
        self._lock = threading.RLock()
        # Map from urlbase to [ nFailures, lastFailureTime ]
        self._mirrorFailures = dict(mirrorFailures)
        # [ nFailures, lastFailureTime ] for the network as a while.
        self._netFailure = list(networkFailures)

    def _getDelay(self, isMirror, failureCount):
        """Return how long we should wait since the 'failureCount'th
           consecutive failure of something before we try it again.
           If isMirror, it's a mirror.  Otherwise, it's the network."""
        if isMirror:
            DELAYS = [ 0, 300, 300, 600, 900, 8400, 8400, 9000 ]
        else:
            DELAYS = [ 0, 10, 30, 30, 60, 300, 600, 1800, 3600, 7200 ]

        if failureCount < len(DELAYS):
            return DELAYS[failureCount]
        else:
            return DELAYS[-1]

    def toJSON(self):
        """Return an object suitable for encoding with json to represent the
           state of this DownloadStatusLog."""
        def formatEnt(e):
            return [ e[0], thandy.formats.formatTime(e[1]) ]
        return { 'v': 1,
                 'networkFailures' : formatEnt(self._netFailure),
                 'mirrorFailures' :
                 dict((k, formatEnt(v)) for k, v
                      in self._mirrorFailures.iteritems())
                 }

    @staticmethod
    def fromJSON(obj):
        _STATUS_LOG_SCHEMA.checkMatch(obj)
        def parseEnt(e):
            return [ e[0], thandy.formats.parseTime(e[1]) ]
        return DownloadStatusLog( dict((k, parseEnt(v)) for k,v
                                        in obj['mirrorFailures'].iteritems()),
                                  parseEnt(obj['networkFailures']))

    def failed(self, failure):
        """Note that 'failure', a DownloadFailure object, has occurred."""
        self._lock.acquire()
        try:
            when = long(failure._when)

            # If there's a mirror to blame, blame it.
            if failure._urlbase != None:
                s = self._mirrorFailures.setdefault(failure._urlbase, [0, 0])
                # XXXX This "+ 5" business is a hack.  The idea is to keep
                # multiple failure within 5 seconds from counting as one,
                # since it's common for us to launch multiple downloads
                # simultaneously.  If we launch 3, and they all fail because
                # the network is down, we want that to count as 1 failure,
                # not 3.
                if s[1] + 5 < when:
                    s[0] += 1
                    s[1] = when

            # If there is no mirror to blame, or we suspect a network error,
            # blame the network too.
            if failure._urlbase == None or failure._network:
                s = self._netFailure
                # see note above.
                if s[1] + 5 < when:
                    s[0] += 1
                    s[1] = when
        finally:
            self._lock.release()

    def succeeded(self, urlbase, url):
        """Note that we have successfully fetched url from the mirror
           at urlbase."""
        self._lock.acquire()
        try:
            try:
                del self._mirrorFailures[urlbase]
            except KeyError:
                pass
            self._netFailure = [0, 0]
        finally:
            self._lock.release()

    def canRetry(self, urlbase=None, now=None):
        """Return True iff we are willing to retry the mirror at urlbase."""
        if now == None:
            now = time.time()

        d = self.getDelayTime(urlbase)
        return d <= now

    def getDelayTime(self, urlbase=None):
        """Return the time after which we're willing to retry fetching from
           urlbase.  0 also means "we're ready now". """
        self._lock.acquire()
        try:
            readyAt = 0

            if urlbase:
                status = self._mirrorFailures.get(urlbase, (0,0))
                if status[1] > readyAt:
                    readyAt = status[1] + self._getDelay(True, status[0])

            if self._netFailure[1] > readyAt:
                readyAt = (self._netFailure[1] +
                           self._getDelay(False, self._netFailure[0]))

            return readyAt
        finally:
            self._lock.release()


class DownloadJob:
    """Abstract base class.  Represents a thing to be downloaded, and the
       knowledge of how to download it."""
    def __init__(self, targetPath, tmpPath, wantHash=None,
                 repoFile=None, useTor=False, wantLength=None):
        """Create a new DownloadJob.  When it is finally downloaded,
           store it in targetPath.  Store partial results in tmpPath;
           if there is already a file in tmpPath, assume that it is an
           incomplete download. If wantHash, reject the file unless
           the hash is as given.  If useTor, use a socks connection.
           If repoFile, use that RepositoryFile to validate the downloaded
           data."""
        self._destPath = targetPath
        self._tmpPath = tmpPath
        self._wantHash = wantHash
        self._wantLength = wantLength
        self._repoFile = repoFile
        self._useTor = useTor

        self._success = lambda : None
        self._failure = lambda : None

    def setCallbacks(self, success, failure):
        """Make sure that 'success' gets called if this download succeeds,
           and 'failure' gets called when it fails.  Both are called from the
           downloader thread, so make sure to be threadsafe."""
        self._success = success
        self._failure = failure

    def getURL(self):
        """Abstract implementation helper.  Returns the URL that the
           _download function downloads from."""
        raise NotImplemented()

    def getMirror(self):
        """Return a string identifying the mirror that's doing the downloading,
           if we know it."""
        return None

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
           when complete.  Return None on success, and a
           DownloadFailure on failure.
        """
        try:
            self._download()
            return None
        except BadCompoundData, err:
            logging.warn("Download failed: %s", err)
            # No way to apportion the blame.
            return DownloadFailure.badCompoundFile(self.getRelativePath())
        except (urllib2.HTTPError, thandy.DownloadError), err:
            # looks like we may have irreconcilable differences with a
            # particular mirror.
            logging.warn("Download failed: %s", err)
            return DownloadFailure.mirrorFailed(self.getMirror(),
                                                self.getRelativePath())
        except (OSError, httplib.error, IOError, urllib2.URLError), err:
            logging.warn("Download failed: %s", err)
            # Could be the mirror; could be the network.  Hard to say.
            return DownloadFailure.connectionFailed(self.getMirror())
        except:
            tp, val, tb = sys.exc_info()
            logging.exception("Internal error during download: %s", val)
            # We have an exception!  Treat it like a network error, I guess.
            return DownloadFailure.connectionFailed(None)

    def setDownloadStatusLog(self, log):
        """Base our URL-picking decisions on the DownloadStatusLog in
           'log'.  The caller is still responsible for invoking the
           logs failed() or succeeded methods.  XXXX is that bad API
           design?"""
        pass

    def _checkTmpFile(self):
        """Helper: check whether the downloaded temporary file matches
           the hash and/or format we need."""
        if self._wantHash and not self._repoFile:
            gotHash = thandy.formats.getFileDigest(self._tmpPath)
            if gotHash != self._wantHash:
                raise thandy.FormatException("File hash was not as expected.")
        elif self._repoFile:
            self._repoFile.checkFile(self._tmpPath, self._wantHash)

    def _removeTmpFile(self):
        """Helper: remove the temporary file so that we do not get stuck in
           a downloading-it-forever loop."""
        os.unlink(self._tmpPath)

    def _download(self):
        # Implementation function.  Unlike download(), can throw exceptions.
        f_in = f_out = None

        haveStalled = self.haveStalledFile()
        if haveStalled and self._wantHash:
            try:
                self._checkTmpFile()
            except thandy.Exception:
                pass
            else:
                # What luck!  This stalled file was what we wanted.
                # (This happens mostly when we have an internal error.)
                thandy.util.ensureParentDir(self._destPath)
                thandy.util.moveFile(self._tmpPath, self._destPath)
                return

        try:
            url = self.getURL()

            logging.info("Downloading %s", url)

            if haveStalled:
                have_length = os.stat(self._tmpPath).st_size
                logging.info("Have stalled file for %s with %s bytes", url,
                             have_length)
                if self._wantLength != None:
                    if self._wantLength >= have_length:
                        logging.warn("Stalled file is too long; removing it")
                        self._removeTmpFile()
                        haveStalled = False
                        have_length = None
            else:
                have_length = None

            try:
                f_in = getConnection(url, self._useTor, have_length)
            except urllib2.HTTPError, err:
                if err.code == 416:
                    # We asked for a range that couldn't be satisfied.
                    # Usually, this means that the server thinks the file
                    # is shorter than we think it is.  We need to start over.
                    self._removeTmpFile()
                raise

            logging.info("Connected to %s", url)

            gotRange = f_in.info().get("Content-Range")
            expectLength = f_in.info().get("Content-Length", "???")
            if gotRange:
                if gotRange.startswith("bytes %s-"%have_length):
                    logging.info("Resuming download from %s"%url)
                    f_out = open(self._tmpPath, 'ab')
                else:
                    raise thandy.DownloadError("Got an unexpected range %s"
                                               %gotRange)
            else:
                f_out = open(self._tmpPath, 'wb')

            total = 0
            while True:
                c = f_in.read(1024)
                if not c:
                    break
                f_out.write(c)
                total += len(c)
                logging.debug("Got %s/%s bytes from %s",
                              total, expectLength, url)
                if self._wantLength != None and total > self._wantLength:
                    logging.warn("Read too many bytes from %s; got %s, but "
                                 "wanted %s", url, total, self._wantLength)
                    break

            if self._wantLength != None and total != self._wantLength:
                logging.warn("Length wrong on file %s", url)

        finally:
            if f_in is not None:
                f_in.close()
            if f_out is not None:
                f_out.close()

        try:
            self._checkTmpFile()
        except (thandy.FormatException, thandy.DownloadError), err:
            self._removeTmpFile()
            if haveStalled:
                raise BadCompoundData(err)
            else:
                raise

        thandy.util.ensureParentDir(self._destPath)
        thandy.util.moveFile(self._tmpPath, self._destPath)


class SimpleDownloadJob(DownloadJob):
    """Testing subtype of DownloadJob: just downloads a URL and writes it to
       disk."""
    def __init__(self, targetPath, url,
                 wantHash=None, supportedURLTypes=None, useTor=False,
                 wantLength=None):
        DownloadJob.__init__(self, targetPath, targetPath+".tmp",
                                 wantHash=wantHash,
                                 wantLength=length,
                                 useTor=useTor)
        self._url = url

    def getURL(self):
        return self._url

    def getRelativePath(self):
        return self._url

def mirrorsThatSupport(mirrorList, relPath, urlTypes=None, statusLog=None):
    """Generator: yields all the mirrors from mirrorList that let us
       fetch from relPath, whose URL type is in urlTypes (if present),
       and who are not marked as failed-too-recently in statusLog (if
       present)."""
    now = time.time()
    for m in mirrorList['mirrors']:
        if urlTypes != None:
            urltype = urllib2.splittype(m['urlbase'])[0]
            if urltype.lower() not in urlTypes:
                continue

        if statusLog != None and not statusLog.canRetry(m['urlbase'], now):
            continue

        for c in m['contents']:
            if thandy.formats.rolePathMatches(c, relPath):
                yield m
                break

class ThandyDownloadJob(DownloadJob):
    """Thandy's subtype of DownloadJob: knows about mirrors, weighting,
       and Thandy's directory structure."""
    def __init__(self, relPath, destPath, mirrorList, wantHash=None,
                 supportedURLTypes=None, useTor=None, repoFile=None,
                 downloadStatusLog=None, wantLength=None):

        DownloadJob.__init__(self, destPath, None, wantHash=wantHash,
                             wantLength=wantLength,
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

        self._usingMirror = None #DOCDOC
        self._downloadStatusLog = downloadStatusLog

    def setDownloadStatusLog(self, log):
        self._downloadStatusLog = log

    def getURL(self):
        usable = []

        for m in mirrorsThatSupport(self._mirrorList, self._relPath,
                                    self._supportedURLTypes,
                                    self._downloadStatusLog):
            usable.append( (m['weight'], m) )

        try:
            mirror = thandy.util.randChooseWeighted(usable)
        except IndexError:
            raise thandy.DownloadError("No mirror supports download.")

        self._usingMirror = mirror['urlbase']

        if m['urlbase'][-1] == '/' and self._relPath[0] == '/':
            return m['urlbase'] + self._relPath[1:]
        else:
            return m['urlbase'] + self._relPath

    def getRelativePath(self):
        return self._relPath

    def getMirror(self):
        return self._usingMirror


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
        headers['Range'] = "bytes=%s-"%have_length

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
