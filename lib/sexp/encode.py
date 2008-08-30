

import base64
import binascii
import re
import hashlib

def _encodeHex(s):
    """
      Encode a string in hex format.

      >>> _encodeHex("Hello world")
      '#48656c6c6f20776f726c64#'
      >>> _encodeHex("")
      '##'
    """
    return "#%s#"%binascii.b2a_hex(s)

def _encodeBase64(s):
    """
       Encode a string in base64 format, with embedded newlines.

       >>> _encodeBase64("")
       '||'
       >>> _encodeBase64("Hello world")
       '|SGVsbG8gd29ybGQ=|'
       >>> print _encodeBase64("Hello world")
       |SGVsbG8gd29ybGQ=|
       >>> _encodeBase64("Good night, sweet prince! A flock of angels "
       ...               "sing thee to thy rest")
       '|R29vZCBuaWdodCwgc3dlZXQgcHJpbmNlISBBIGZsb2NrIG9mIGFuZ2VscyBzaW5nIHRoZWUgdG8g\\ndGh5IHJlc3Q=|'

    """
    return "|%s|"%base64.encodestring(s).strip()

# Map from a character value to its representation in a quoted-string.
_QUOTED_MAP = { '\b' : "\\b",
                '\t' : "\\t",
                '\v' : "\\v",
                '\n' : "\\n",
                '\f' : "\\f",
                '\r' : "\\r",
                '"'  : "\"",
                '\b' : "\\b",
                '\\' : "\\", }
for x in xrange(256):
    if 32 <= x <= 126:
        _QUOTED_MAP[chr(x)] = chr(x)
    elif not _QUOTED_MAP.has_key(chr(x)):
        _QUOTED_MAP[chr(x)] = "\\x%02x"%x
del x


_QUOTED_CHAR_RE = re.compile(r'[^\ -\~]')
def _replaceQuotedChar(match, _Q=_QUOTED_MAP):
    """Helper function for replacing ."""
    return _Q[match.group(0)]

def _encodeQuoted(s, _Q=_QUOTED_MAP):
    """
       >>> _encodeQuoted("")
       '""'
       >>> _encodeQuoted("Hello world")
       '"Hello world"'
       >>> print _encodeQuoted("Hello \xff\b")
       "Hello \\xff\\b"
    """
    # This implementation is a slower for the case where lots of stuff
    # needs quoting, but faster for the case where only some stuff
    # needs quoting.  If more than about 1/4 of the characters need
    # quoting, then the commented-out version below is faster.  Yes,
    # this is a stupid overoptimization.
    return '"%s"'%(_QUOTED_CHAR_RE.sub(_replaceQuotedChar, s))

    #return '"%s"'%("".join(map(_QUOTED_MAP.__getitem__, s)))

def _encodeRaw(s):
    """
       Encode a string in the "raw" format used for canonical encodings.

       >>> _encodeRaw("")
       '0:'
       >>> _encodeRaw(" ")
       '1: '
       >>> _encodeRaw(" \\n")
       '2: \\n'
    """
    return "%d:%s"%(len(s),s)

_TOKEN_PAT = r"[a-zA-Z\-\.\/\_\:\*\+\=][a-zA-Z0-9\-\.\/\_\:\*\+\=]*"

_TOKEN_RE = re.compile(_TOKEN_PAT)
def _writeToken(write,s):
    """Write a string in the token (unencoded) format.  Only works for strings
       matching _TOKEN_RE.
    """
    assert _TOKEN_RE.match(s)
    return s

def _encodeCleanest(s, indent=0):
    """Encode s in whatever format seems most human-readable."""

    if _TOKEN_RE.match(s):
        return s
    n = 0
    for ch in s:
        if _QUOTED_MAP[ch] != ch:
            n += 1
    if n > 3 and n > len(s)//4:
        if len(s) > 16:
            return _encodeBase64(s).replace("\n", " "*(indent+1)+"\n")
        else:
            return _encodeHex(s)
    else:
        return _encodeQuoted(s)

def _encodePrettyPrint(s, write, indent=0, niceWidth=80):
    if isinstance(s, str):
        write(_encodeCleanest(s))
        return
    elif len(s) == 0:
        write("()")
        return

    if isinstance(s[0], str):
        parts = [ " "*indent, "(", _encodeCleanest(s), "\n" ]
    else:
        parts = [ "(" ]

def _encodeCanonical(rep, append):
    """Given an s-expression in <rep>, encode it in canonical format,
       passing each part to the function "append" as it is done.
    """
    if isinstance(rep, str):
        append(_encodeRaw(rep))
        return

    append("(")

    stack = [ ]
    push = stack.append
    pop = stack.pop
    idx = 0
    while 1:
        while idx == len(rep):
            append(")")
            try:
                rep,idx = pop()
            except IndexError:
                return
        if isinstance(rep[idx], str):
            append(_encodeRaw(rep[idx]))
            idx += 1
            continue
        push((rep,idx+1))
        rep = rep[idx]
        idx = 0
        append("(")

def encode_canonical(rep):
    """Return the canonical encoding of the s-expression <rep>.

       >>> encode_canonical("abc")
       '3:abc'
       >>> encode_canonical(["a"])
       '(1:a)'
       >>> encode_canonical(["a", "bc"])
       '(1:a2:bc)'
       >>> encode_canonical([[["X", "ab c"]], "d"])
       '(((1:X4:ab c))1:d)'
    """
    parts = []
    _encodeCanonical(rep, parts.append)
    return "".join(parts)

def hash_canonical(rep, hashobj):
    """Given a hashlib hash object <hashobj>, adds the canonical
       encoding of the s-expression <rep> to hashobj.

       >>> import hashlib
       >>> s = hashlib.sha256()
       >>> s.update("(3:abc(6:hello 5:world)(1:9))")
       >>> s.hexdigest()
       '43f7726155f2700ff0d84240f3aaa9e5a1ee2e2c9e4702f7ac3ebcd45fd2f397'
       >>> s = hashlib.sha256()
       >>> hash_canonical(["abc", ["hello ", "world"], ["9"] ], s)
       >>> s.hexdigest()
       '43f7726155f2700ff0d84240f3aaa9e5a1ee2e2c9e4702f7ac3ebcd45fd2f397'
    """
    _encodeCanonical(rep, hashobj.update)

def _encodePretty(rep, append, indent_step=2, niceWidth=80):
    stack = []
    idx = 0
    indent = 0
    append("(")
    pop = stack.pop
    push = stack.append

    while 1:
        while idx == len(rep):
            append(")")
            indent -= indent_step
            try:
                rep,idx = pop()
            except IndexError:
                append("\n")
                return
            else:
                append(" ")
        if isinstance(rep[idx], str):
            _encodePrettyPrint(rep[idx], append, indent, niceWidth)
            idx += 1
            if idx < len(rep):
                append(" ")
            continue
        push((rep,idx+1))
        rep = rep[idx]
        idx = 0
        indent += indent_step
        append("\n%s("%(" "*indent))


