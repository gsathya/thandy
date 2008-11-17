# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import getopt
import logging
import os
import sys
import time

import thandy.formats
import thandy.util
import thandy.repository
import thandy.download
import thandy.master_keys
import thandy.packagesys.PackageSystem
import thandy.socksurls

def update(args):
    repoRoot = thandy.util.userFilename("cache")
    options, args = getopt.getopt(args, "", [ "repo=", "no-download",
                                              "loop", "no-packagesys",
                                              "install", "socks-port=",
                                              "debug", "info",
                                              "warn"])
    download = True
    keep_looping = False
    use_packagesys = True
    install = False
    socksPort = None
    logLevel = logging.INFO

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

    logging.basicConfig(level=logLevel)

    if socksPort:
        thandy.socksurls.setSocksProxy("127.0.0.1", socksPort)

    repo = thandy.repository.LocalRepository(repoRoot)
    packagesys = None
    if use_packagesys:
        packagesys = thandy.packagesys.PackageSystem.PackageMetasystem.create(repo)

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

        downloader = thandy.download.DownloadManager()

        for f in files:
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

            downloader.addDownloadJob(dj)

        logging.debug("Launching downloads")
        downloader.start()

        logging.debug("Waiting for downloads to finish.")
        downloader.wait()
        logging.info("All downloads finished.")


# Tell me what to install.


def usage():
    print "Known commands:"
    print "  update [--repo=repository] [--no-download] [--loop]"
    print "         [--no-packagesys] [--install] [--socks-port=port]"
    print "         [--debug|--info|--warn]"
    sys.exit(1)

def main():

    if len(sys.argv) < 2:
        usage()
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd in [ "update" ]:
        globals()[cmd](args)
    else:
        usage()

if __name__ == '__main__':
    main()
