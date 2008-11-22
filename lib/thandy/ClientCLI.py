# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import getopt
import logging
import os
import sys
import time
try:
    import json
except ImportError:
    import simplejson as json

import thandy.formats
import thandy.util
import thandy.repository
import thandy.download
import thandy.master_keys
import thandy.packagesys.PackageSystem
import thandy.socksurls
import thandy.encodeToXML

def update(args):
    repoRoot = thandy.util.userFilename("cache")
    options, args = getopt.getopt(args, "", [ "repo=", "no-download",
                                              "loop", "no-packagesys",
                                              "install", "socks-port=",
                                              "debug", "info",
                                              "warn", "force-check"])
    download = True
    keep_looping = False
    use_packagesys = True
    install = False
    socksPort = None
    logLevel = logging.INFO
    forceCheck = False

    for o, v in options:
        if o == '--repo':
            repoRoot = v
        elif o == "--no-download":
            download = False
        elif o == '--loop':
            keep_looping = True
        elif o == '--no-packagesys':
            use_packagesys = False
        elif o == '--install':
            install = True
        elif o == "--socks-port":
            socksPort = int(v)
        elif o == '--debug':
            logLevel = logging.DEBUG
        elif o == '--info':
            logLevel = logging.INFO
        elif o == '--warn':
            logLevel = logging.WARN
        elif o == '--force-check':
            forceCheck = True

    logging.basicConfig(level=logLevel)

    if socksPort:
        thandy.socksurls.setSocksProxy("127.0.0.1", socksPort)

    repo = thandy.repository.LocalRepository(repoRoot)
    packagesys = None
    if use_packagesys:
        packagesys = thandy.packagesys.PackageSystem.PackageMetasystem.create(repo)

    downloader = thandy.download.DownloadManager()
    downloader.start()

    # XXXX We could make this loop way smarter.  Right now, it doesn't
    # back off between failures, and it doesn't notice newly downloadable files
    # until all downloading files are finished.
    while True:
        hashes = {}
        installable = {}
        logging.info("Checking for files to update.")
        files = repo.getFilesToUpdate(trackingBundles=args, hashDict=hashes,
                                      pkgSystems=packagesys,
                                      installableDict=installable)

        if forceCheck:
            files.add("/meta/timestamp.txt")
            forceCheck = False

        if installable and not files:
            logging.info("Ready to install files: %s",
                           ", ".join(sorted(installable.keys())))
            if install:
                # XXXX handle ordering
                for h in installable.values():
                    h.install()
            return

        elif not files:
            logging.info("No files to download")
            if not keep_looping:
                return

            ts = repo.getTimestampFile().get()
            age = time.time() - thandy.formats.parseTime(ts['at'])
            delay = thandy.repository.MAX_TIMESTAMP_AGE - age
            if delay > 3600:
                delay = 3600
            elif delay < 0:
                delay = 300
            logging.info("Will check again in %s seconds", delay)
            time.sleep(delay)
            continue

        logging.info("Files to download are: %s", ", ".join(sorted(files)))

        if not download:
            return

        mirrorlist = repo.getMirrorlistFile().get()
        if not mirrorlist:
            mirrorlist = thandy.master_keys.DEFAULT_MIRRORLIST

        if files:
            waitTill = min(downloader.getRetryTime(mirrorlist, f)
                           for f in files)
            now = time.time()
            if waitTill > now:
                delay = int(waitTill - now) + 1
                logging.info("Waiting another %s seconds before we are willing "
                             "to retry any mirror.", delay)
                time.sleep(delay)
                continue

        logging.debug("Launching downloads")
        now = time.time()
        for f in files:
            if downloader.getRetryTime(mirrorlist, f) > now:
                logging.info("Waiting a while before we fetch %s", f)
                continue

            dj = thandy.download.ThandyDownloadJob(
                f, repo.getFilename(f),
                mirrorlist,
                wantHash=hashes.get(f),
                repoFile=repo.getRequestedFile(f),
                useTor=(socksPort!=None))

            def successCb(rp=f):
                rf = repo.getRequestedFile(rp)
                if rf != None:
                    rf.clear()
                    rf.load()
            def failCb(): pass
            dj.setCallbacks(successCb, failCb)

            downloader.addDownloadJob(dj)

        logging.debug("Waiting for downloads to finish.")
        downloader.wait()
        logging.info("All downloads finished.")


def json2xml(args):
    if len(args) != 1:
        usage()
    f = open(args[0], 'r')
    obj = json.load(f)
    f.close()
    thandy.encodeToXML.encodeToXML(obj, sys.stdout.write)

def usage():
    print "Known commands:"
    print "  update [--repo=repository] [--no-download] [--loop]"
    print "         [--no-packagesys] [--install] [--socks-port=port]"
    print "         [--debug|--info|--warn] [--force-check]"
    print "  json2xml file"
    sys.exit(1)

def main():

    if len(sys.argv) < 2:
        usage()
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd in [ "update", "json2xml" ]:
        globals()[cmd](args)
    else:
        usage()

if __name__ == '__main__':
    main()
