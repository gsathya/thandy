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

def update(args):
    repoRoot = thandy.util.userFilename("cache")
    options, args = getopt.getopt(args, "", [ "repo=", "no-download",
                                              "loop", "no-packagesys",
                                              "install"])
    download = True
    keep_looping = False
    use_packagesys = True
    install = False

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

    repo = thandy.repository.LocalRepository(repoRoot)
    packagesys = None
    if use_packagesys:
        packagesys = thandy.packagesys.PackageSystem.PackageMetasystem.create(repo)

    while True:
        hashes = {}
        installable = {}
        logging.info("Checking for files to update.")
        files = repo.getFilesToUpdate(trackingBundles=args, hashDict=hashes,
                                      pkgSystems=packagesys,
                                      installableDict=installable)

        if installable and not files:
            logging.notice("Ready to install files: %s",
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
            dj = thandy.download.ThandyDownloadJob(f, repo.getFilename(f),
                                                   mirrorlist,
                                                   wantHash=hashes.get(f))

            def successCb(rp=f):
                rf = repo.getRequestedFile(rp)
                if rf != None:
                    rf.clear()
                    rf.load()

            downloader.addDownloadJob(dj)

        logging.info("Launching downloads")
        downloader.start()

        logging.info("Waiting for downloads to finish.")
        downloader.wait()
        logging.info("All downloads finished.")


# Tell me what to install.


def usage():
    print "Known commands:"
    print "  update [--repo=repository] [--no-download] [--loop]"
    print "         [--no-packagesys] [--install]"
    sys.exit(1)

def main():
    #XXXX make this an option.
    logging.basicConfig(level=logging.DEBUG)

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
