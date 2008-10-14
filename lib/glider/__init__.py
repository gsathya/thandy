
__all__ = [ 'formats' ]

_BaseException = Exception

class Exception(_BaseException):
    pass

class FormatException(Exception):
    pass

class UnknownFormat(FormatException):
    pass

class BadSignature(Exception):
    pass

class BadPassword(Exception):
    pass

class InternalError(Exception):
    pass

class RepoError(InternalError):
    pass

class CryptoError(Exception):
    pass

class PubkeyFormatException(FormatException):
    pass

class UnknownMethod(CryptoError):
    pass

