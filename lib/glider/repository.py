
import sexp.parse
import sexp.access
import glider.formats

import os
import threading

class RepositoryFile:
    def __init__(self, repository, relativePath, schema,
                 needRole=None, signedFormat=True, needSigs=1):
        self._repository = repository
        self._relativePath = relativePath
        self._schema = schema
        self._needRole = needRole
        self._signedFormat = signedFormat
        self._needSigs = needSigs

        self._signed_sexpr = None
        self._main_sexpr = None
        self._mtime = None

    def getPath(self):
        return os.path.join(self._repository._root, self._relativePath)

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

        signed_sexpr,main_sexpr = self._checkContent(content)

        self._signed_sexpr = signed_sexpr
        self._main_sexpr = main_sexpr
        self._mtime = mtime

    def _save(self, content=None):
        if content == None:
            content = sexpr.encode

        signed_sexpr,main_sexpr = self._checkContent(content)

        fname = self.getPath()
        fname_tmp = fname+"_tmp"

        fd = os.open(fname_tmp, os.WRONLY|os.O_CREAT|os.O_TRUNC, 0644)
        try:
            os.write(fd, contents)
        finally:
            os.close(fd)
        if sys.platform in ('cygwin', 'win32'):
            # Win32 doesn't let rename replace an existing file.
            try:
                os.unlink(fname)
            except OSError:
                pass
        os.rename(fname_tmp, fname)

        self._signed_sexpr = signed_sexpr
        self._main_sexpr = main_sexpr
        self._mtime = mtime

    def _checkContent(self, content):
        sexpr = sexp.parse.parse(content)
        if not sexpr:
            raise ParseError()

        if self._signedFormat:
            if not glider.formats.SIGNED_SCHEMA.matches(sexpr):
                raise FormatError()

            sigs = checkSignatures(sexpr, self._repository._keyDB,
                                   self._needRole, self._relativePath)
            good = sigs[0]
            # XXXX If good is too low but unknown is high, we may need
            # a new key file.
            if len(good) < 1:
                raise SignatureError()

            main_sexpr = sexpr[1]
            signed_sexpr = sexpr
        else:
            signed_sexpr = None
            main_sexpr = sexpr

        if self._schema != None and not self._schema.matches(main_sexpr):
            raise FormatError()

        return signed_sexpr, main_sexpr

    def load(self):
        if self._main_sexpr == None:
            self._load()

class LocalRepository:
    def __init__(self, root):
        self._root = root
        self._keyDB = None

        self._keylistFile = RepositoryFile(
            self, "meta/keys.txt", glider.formats.KEYLIST_SCHEMA,
            needRole="master")
        self._timestampFile = RepositoryFile(
            self, "meta/timestamp.txt", glider.formats.TIMESTAMP_SCHEMA,
            needRole="timestamp")
        self._mirrorlistFile = RepositoryFile(
            self, "meta/mirrors.txt", glider.formats.MIRRORLIST_SCHEMA,
            needRole="mirrors")

