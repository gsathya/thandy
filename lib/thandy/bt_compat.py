# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import os.path
import time

import thandy.master_keys

no_bt = None
try:
    import BitTorrent.bencode
    import BitTorrent.btformats
    import BitTorrent.download
except ImportError:
    no_bt = True
from sha import sha # XXX Use PyCrypto here?


class BtCompat:
    """Interface for different bittorrent implementations"""

    usingBt = False

    def __init__(self):
        self.tUrl = thandy.master_keys.DEFAULT_TRACKER
        if not no_bt:
            assert(self.tUrl is not None and self.tUrl != "")
        self.pieceLength = 2 ** 18 # Piece length of 262144 bytes

    # XXX Do we need to be thread-safe here and below?
    @staticmethod
    def shouldUseBt():
        return BtCompat.usingBt

    @staticmethod
    def setUseBt(useBt):
        if no_bt:
            return
        BtCompat.usingBt = useBt

    @staticmethod
    def getBtMetadataLocation(packagepath, filepath, pathprefix=""):
        """Given a path for the package, the path for a file of that
           package, and an optional prefix, return the path for the
           .torrent metadata file. Always return Unix-like paths, to
           ensure compatibility with fetching the path from a
           webserver.
        """
        return (os.path.join(pathprefix, os.path.dirname(packagepath),
                             os.path.basename(filepath)) + ".torrent"
               ).replace("\\", "/")

    def makeMetaFile(self, file):
        """Given a path to a file, create the contents of a .torrent
           metadata file and return them.
        """
        size = os.path.getsize(file)
        filename = os.path.basename(file)
        pieces = []
        p = 0
        h = open(file, 'rb')
        while p < size:
            x = h.read(min(self.pieceLength, size - p))
            pieces.append(sha(x).digest())
            p += self.pieceLength
            if p > size:
                p = size
        h.close()
        info = {'pieces': ''.join(pieces),
            'piece length': self.pieceLength, 'length': size,
            'name': filename}
        # Check we didn't screw up with the info
        BitTorrent.btformats.check_info(info)
        data = {'info': info, 'announce': self.tUrl,
                'creation date': long(time.time())}
        return BitTorrent.bencode.bencode(data)

