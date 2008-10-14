
import os
import sys
import getopt

import glider.util
import glider.repository
import glider.download

def update(args):
    repoRoot = glider.util.userFilename("cache")
    options, args = getopt.getopt(args, "", [ "repo=", "no-download" ])
    download = True

    for o, v in options:
        if o == '--repo':
            repoRoot = v
        elif o == "--no-download":
            download = False

    repo = glider.repository.LocalRepository(repoRoot)

    files = repo.getFilesToUpdate(trackingBundles=args)

    if not download:
        return

    mirrorlist = repo.getMirrorlistFile().get()

    downloader = glider.download.Downloads()
    downloader.start()

    for f in files:
        # XXXX Use hash.
        dj = glider.download.DownloadJob(f, repo.getFilename(f),
                                         mirrorlist)
        downloader.addDownloadJob(dj)
        # XXXX replace file in repository if ok; reload; see what changed.
    
    # Wait for in-progress jobs

# Check my repository

# Tell me what I need to download

# Download stuff

# Tell me what to install.

def usage():
    print "Known commands:"
    print "  update [--repo=repository] [--no-download]"
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
