
import re
import base64
import binascii
import re

# Partial implementation of Rivest's proposed S-Expressions standard
# as documented at
#      http://people.csail.mit.edu/rivest/Sexp.txt
#
# It's slightly optimized.
#
# Not implemented:
#    [display hints]
#    {basic transport}

__all__ = [ 'FormatError', 'parse' ]

class FormatError(Exception):
    """Raised when parsing fails."""
    pass

_TOKEN_PAT = r"[a-zA-Z\-\.\/\_\:\*\+\=][a-zA-Z0-9\-\.\/\_\:\*\+\=]*"
# Regular expression to match a single lexeme from an encode s-expression.
_LEXEME_START_RE = re.compile(
    r""" \s* (?: (%s) |     # Grp 0: A token.
                 ([0-9]*(?: [\:\|\#\{]  |   # Grp1 : start of string...
                            \"(?:[^\\\"]+|\\.)*\"))  | # or qstring.
                 ([\(\)])  # Grp 2: a paren of some kind.
              )"""
                              %_TOKEN_PAT,re.X|re.M|re.S)

class _P:
    """Helper class for parenthesis tokens."""
    def __init__(self, val):
        self.val = val
    def __repr__(self):
        return "_P(%r)"%self.val

_OPEN_PAREN = _P("(")
_CLOSE_PAREN = _P(")")
del _P
_SPACE_RE = re.compile(r'\s+')

# Matches all characters in a string that we need to unquote.
_UNQUOTE_CHAR_RE = re.compile(r'''
     \\  (?: [abtnvfr] | \r \n ? | \n \r ? | [xX] [A-Fa-f0-9]{2} | [0-8]{1,3} )
     ''')

# Map from quoted representation to unquoted format.
_UNQUOTE_CHAR_MAP = { 'a': '\a',
                      'b': '\b',
                      't': '\t',
                      'n': '\n',
                      'v': '\v',
                      'f': '\f',
                      'r': '\r' }
def _unquoteChar(ch, _U=_UNQUOTE_CHAR_MAP):
    ch = ch[1:]
    try:
        return _U[ch]
    except KeyError:
        pass
    if ch[0] in "\n\r":
        return ""
    elif ch[0] in 'xX':
        return chr(int(ch[1:], 16))
    else:
        i = int(ch[1:], 8)
        if i >= 256:
            raise FormatError("Octal character format out of range.")
        return chr(i)

def _lexItems(s):
    """Generator that iterates over the lexical items in an encoded
       s-expression.  Yields a string for strings, or the special objects
       _OPEN_PAREN and _CLOSE_PAREN.

       >>> list(_lexItems('(4:a)b   hello) (world 1:a 0: '))
       [_P('('), 'a)b ', 'hello', _P(')'), _P('('), 'world', 'a', '']

       >>> list(_lexItems('a b-c 1#20#2#2061##686877# |aGVsbG8gd29ybGQ|'))
       ['a', 'b-c', ' ', ' a', 'hhw', 'hello world']

       >>> list(_lexItems('#2 0# |aGVs\\nbG8 gd29yb   GQ|  '))
       [' ', 'hello world']

       >>> list(_lexItems('|YWJjZA==| x |YWJjZA| 3|Y   W J  j|'))
       ['abcd', 'x', 'abcd', 'abc']

       >>> list(_lexItems('("1""234""hello world" 3"abc" 4"    " )'))
       [_P('('), '1', '234', 'hello world', 'abc', '    ', _P(')')]

    """
    s = s.strip()
    while s:
        m = _LEXEME_START_RE.match(s)
        if not m:
            raise FormatError("No pattern match at %r"%s[:30])
        g = m.groups()
        if g[2]:
            if g[2] == "(":
                yield _OPEN_PAREN
            else:
                yield _CLOSE_PAREN
            s = s[m.end():]
        elif g[0]:
            # we have a token.  Go with that.
            yield g[0]
            s = s[m.end():]
        else:
            assert g[1]
            lastChar = g[1][-1]
            if lastChar == '"':
                qidx = g[1].index('"')
                quoted = g[1][qidx+1:-1] # All but quotes.
                data = _UNQUOTE_CHAR_RE.sub(_unquoteChar, quoted)
                if qidx != 0:
                    num = int(g[1][:qidx], 10)
                    if num != len(data):
                        raise FormatError("Bad length on quoted string")
                yield data
                s = s[m.end():]
                continue

            num = g[1][:-1]
            if len(num):
                num = int(num, 10)
            else:
                num = None

            if lastChar == ':':
                if num is None:
                    raise FormatError()
                s = s[m.end():]
                if len(s) < num:
                    raise FormatError()
                yield s[:num]
                s = s[num:]
            elif lastChar == '#':
                s = s[m.end():]
                try:
                    nextHash = s.index('#')
                except ValueError:
                    raise FormatError("Unterminated # string")
                dataStr = _SPACE_RE.sub("", s[:nextHash])
                try:
                    data = binascii.a2b_hex(dataStr)
                except TypeError:
                    raise FormatError("Bad hex string")
                if num is not None and len(data) != num:
                    raise FormatError("Bad number on hex string")
                yield data
                s = s[nextHash+1:]
            elif lastChar == '|':
                s = s[m.end():]
                try:
                    nextBar = s.index('|')
                except ValueError:
                    raise FormatError("Unterminated | string")
                dataStr = _SPACE_RE.sub("", s[:nextBar])
                # Re-pad.
                mod = len(dataStr) % 4
                if mod:
                    dataStr += "=" * (4 - mod)
                try:
                    data = binascii.a2b_base64(dataStr)
                except TypeError:
                    raise FormatError("Bad base64 string")
                if num is not None and len(data) != num:
                    raise FormatError("Bad number on base64 string")
                yield data
                s = s[nextBar+1:]
            else:
                assert None

def parse(s):
    """
       >>> parse("()")
       []
       >>> parse("(1:X3:abc1:d)")
       ['X', 'abc', 'd']
       >>> parse("(1:X((3:abc))1:d)")
       ['X', [['abc']], 'd']
       >>> parse("(a b (d\\ne f) (g) #ff00ff# |aGVsbG8gd29ybGQ|)")
       ['a', 'b', ['d', 'e', 'f'], ['g'], '\\xff\\x00\\xff', 'hello world']

    """
    outermost = []
    stack = [ ]
    push = stack.append
    pop = stack.pop
    add = outermost.append

    for item in _lexItems(s):
        if item is _OPEN_PAREN:
            next = []
            add(next)
            push(add)
            add = next.append
        elif item is _CLOSE_PAREN:
            add = pop()
        else:
            # it's a string.
            add(item)

    if len(outermost) != 1:
        raise FormatError("No enclosing parenthesis on list")
    return outermost[0]

