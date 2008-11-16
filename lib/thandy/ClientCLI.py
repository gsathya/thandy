# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import getopt
import logging
import os
import sys

import thandy.util
import thandy.repository
import thandy.download
import thandy.master_keys

def update(args):
    repoRoot = thandy.util.userFilename("cache")
    options, args = getopt.getopt(args, "", [ "repo=", "no-download" ])
    download = True

    for o, v in options:
        if o == '--repo':
            repoRoot = v
        elif o == "--no-download":
            download = False

    repo = thandy.repository.LocalRepository(repoRoot)

    while True:
        hashes = {}
        logging.info("Checking for files to update.")
        files = repo.getFilesToUpdate(trackingBundles=args, hashDict=hashes)
        logging.info("Files to download are: %s", ", ".join(sorted(files)))

        if not download or not files:
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


# Check my repository

# Tell me what I need to download

# Download stuff

# Tell me what to install.


def usage():
    print "Known commands:"
    print "  update [--repo=repository] [--no-download]"
    sys.exit(1)

def main():
    #XXXX make this an option.
    logging.basicConfig(level=logging.DEBUG)

    if len(sys.argv) < 2:
        usage()
    cmd = sys.argv[1]
    args = sys.argv[2:]
    if cmd in [ "update", "geturls" ]:
        globals()[cmd](args)
    else:
        usage()

if __name__ == '__main__':
    main()
