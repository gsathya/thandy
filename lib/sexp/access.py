
import re
import sys

def s_tag(s):
    """
    >>> s_tag("a string") is None
    True
    >>> s_tag(["a-tagged", "list"])
    'a-tagged'
    >>> s_tag([["untagged"], "list"]) is None
    True
    """
    if len(s) and not isinstance(s, str) and isinstance(s[0],str):
        return s[0]
    else:
        return None

def s_child(s, tag):
    for child in s:
        if s_tag(child) == tag:
            return child
    return None

def s_children(s, tag):
    return (ch for ch in s if s_tag(ch) == tag)

def s_descendants(s, tags=()):
    stack = [ ]
    push = stack.append
    pop = stack.pop

    idx = 0
    while 1:
        while idx == len(s):
            try:
                s, idx = pop()
            except IndexError:
                return
        if isinstance(s[idx], str):
            idx += 1
            continue
        if s_tag(s[idx]) in tags:
            yield s[idx]


class SExpr(list):
    def __init__(self, stuff=()):
        list.__init__(self, stuff)
        self._d = None

    def __getattr__(self, item):
        if self._d is None: self._buildDict()
        return self[self._d[item]]

    def __getitem__(self, idx):
        item = list.__getitem__(self, idx)
        if type(item) in (list, tuple): #exact match only.
            item = self[idx] = SExpr(item)
        return item

    def _buildDict(self):
        self._d = d = {}
        for idx in xrange(len(self)):
            item = list.__getitem__(self, idx)
            t = s_tag(item)
            if t is not None:
                d[t] = idx

def _s_lookup_all(s, path, callback):

    # XXXX: Watch out; ** gets pretty heavy pretty fast.

    if isinstance(path, str):
        path = path.split(".")

    if len(path) == 0:
        callback(s)
        return

    for p_idx in xrange(len(path)):
        p_item = path[p_idx]

        if p_item == '*':
            for ch in s:
                if not isinstance(ch, str):
                    _s_lookup_all(s, path[p_idx+1:], callback)
            return
        elif p_item == '**':
            for ch in s_descendants(s):
                if not isinstance(ch, str):
                    _s_lookup_all(s, path[p_idx+1:], callback)
            return
        elif p_item.startswith('**'):
            for ch in s_descendants(s):
                if s_tag(ch) == p_item[2:]:
                    _s_lookup_all(s, path[p_idx+1:], callback)
        else:
            s = s_child(s, p_item)
            if s is None:
                return

    callback(s)

def s_lookup_all(s, path):
    result = []
    _s_lookup_all(s, path, result.append)
    return result

def s_lookup(s, path):
    r = s_lookup_all(s, path)
    if len(r):
        return r[0]
    return None

class _Singleton:
    def isSingleton(self):
        return True
    def matches(self, item):
        raise NotImplemented()

    def clear(self):
        self._got = False
    def matchItem(self, item):
        if not self._got and self.matches(item):
            self._got = True
            return True
        else:
            return False
    def isSatisfied(self):
        return self._got

class _Span:
    def isSingleton(self):
        return False
    def clear(self):
        pass
    def matchItem(self, item):
        raise NotImplemented()
    def isSatisfied(self):
        raise NotImplemented()

class _AnyItem(_Singleton):
    def matches(self,item):
        return True
    def rep(self):
        return "?"
class _AnyString(_Singleton):
    def matches(self,item):
        return isinstance(item, str)
    def rep(self):
        return "."
class _ExactString(_Singleton):
    def __init__(self, s):
        self._s = s
    def matches(self, item):
        return item == self._s
    def rep(self):
        return "=%s"%self._s
class _ReString(_Singleton):
    def __init__(self, s, regex=None):
        if regex is None:
            regex = re.compile(s)
        self._re = regex
        self._s = s
    def matches(self, item):
        if not isinstance(item, str):
            return False
        m = self._re.match(item)
        return m and m.end() == len(item)
    def rep(self):
        return "%s"%self._s
class _List(_Singleton):
    def __init__(self, subpatterns):
        self._pats = subpatterns
    def clear(self):
        _Singleton.clear(self)
        for p in self._pats:
            p.clear()
    def matches(self, item):
        if isinstance(item, str):
            return False

        i_idx = 0
        pat_idx = 0
        while i_idx < len(item):
            try:
                subpat = self._pats[pat_idx]
            except:
                return False # Too many items.

            if subpat.isSingleton():
                if not subpat.matches(item[i_idx]):
                    return False
                i_idx += 1
                pat_idx += 1
            else:
                subpat.clear()
                while i_idx < len(item) and subpat.matchItem(item[i_idx]):
                    i_idx += 1
                if not subpat.isSatisfied():
                    return False
                pat_idx += 1

        # Out of items, but we have more patterns.  Make sure they all accept
        # 0 items.
        if pat_idx < len(self._pats):
            for subpat in self._pats[pat_idx:]:
                subpat.clear()
                if not subpat.isSatisfied():
                    return False
        return True

    def rep(self):
        return [ p.rep() for p in self._pats ]

class _AnyItems(_Span):
    def matchItem(self, item):
        return True
    def isSatisfied(self):
        return True
    def rep(self):
        return "*"

class _NMatches(_Span):
    def __init__(self, alternatives, lo, hi):
        self.lo = lo
        self.hi = hi
        self.count = 0
        self.alternatives = alternatives
        for a in alternatives:
            if not a.isSingleton():
                raise SchemaFormatError("Nexted span inside span")
    def clear(self):
        self.count = 0
        for p in self.alternatives:
            p.clear()
    def matchItem(self, item):
        if self.count == self.hi:
            return False
        for p in self.alternatives:
            if p.matches(item):
                self.count += 1
                return True
        return False
    def isSatisfied(self):
        return self.lo <= self.count <= self.hi

    def rep(self):
        name = { (1,1): ":oneof",
                 (0,1): ":maybe",
                 (0,sys.maxint): ":anyof",
                 (1,sys.maxint): ":someof" }.get((self.lo, self.hi))
        if name is None:
            name = ":%d-%d"%(self.lo, self.hi)
        result = [ name ]
        result.extend(p.rep() for p in self.alternatives)
        return result

class _Unordered(_Span):
    def __init__(self, alternatives):
        self.alternatives = alternatives
    def clear(self):
        for p in self.alternatives:
            p.clear()
    def matchItem(self, item):
        for p in self.alternatives:
            if p.matchItem(item):
                return True
        return False
    def isSatisfied(self):
        for p in self.alternatives:
            if not p.isSatisfied():
                return False
        return True
    def rep(self):
        result = [ ":unordered" ]
        result.extend(p.rep() for p in self.alternatives)
        return result

class SchemaFormatError(Exception):
    pass

_RE_PAT = re.compile(r'/((?:[\\.]|[^\\/]+)*)/([ilmstx]*)', re.I)

def parseSchema(s, table):

    if isinstance(s, str):
        if not len(s):
            raise SchemaFormatError("Empty string encountered")
        if s == '*':
            return _AnyItems()
        elif s == '?':
            return _AnyItem()
        elif s == '.':
            return _AnyString()
        elif s.startswith('='):
            return _ExactString(s[1:])
        elif s.startswith('.'):
            try:
                return table[s[1:]]
            except KeyError:
                raise SchemaFormatError("Unknown reference %s"%s)
        else:
            m = _RE_PAT.match(s)
            if m:
                flags = 0
                for char in m.group(2):
                    flags |= { "i":re.I, "l":re.L, "m":re.M, "s":re.S,
                               "t":re.T, "x":re.X }[char.lower()]
                try:
                    p = re.compile(m.group(1), flags)
                except re.error, e:
                    raise SchemaFormatError("Couldn't compile %s"%s)

                return _ReString(s, p)

            raise SchemaFormatError("Confusing entry %s"%s)
    elif len(s) and isinstance(s[0], str) and s[0].startswith(':'):
        tag = s[0]

        m = re.match(r'\:(\d*)(\-\d*)?$', tag)
        if m:
            g = m.groups()
            if g[0]:
                lo = int(g[0], 10)
            else:
                lo = 0
            if g[1]:
                if len(g[1]) > 1:
                    hi = int(g[1][1:], 10)
                else:
                    hi = sys.maxint
            else:
                hi = lo
        else:
            try:
                lo,hi = { ":maybe": (0,1),
                          ":oneof": (1,1),
                          ":anyof": (0,sys.maxint),
                          ":someof":(1,sys.maxint),
                          ":unordered": (None, None) }[tag]
            except KeyError:
                raise SchemaFormatError("Unknown tag %s"%tag)

        subitems = [ parseSchema(i, table) for i in s[1:] ]
        if lo is not None:
            return _NMatches(subitems, lo, hi)
        else:
            return _Unordered(subitems)
    else:
        return _List([ parseSchema(i, table) for i in s ])

# Schema format:
#   "=string" matches a string itself.
#   "*" matches any number of items and can occur only at the end of a list.
#   "?" matches a single item.
#   "." matches any string.
#   "/re/" matches a regex.
#   ".name" matches a named schema
#
#   (i1 i2 i3)         matches a list of i1 followed by i2 followed by i3.
#
#   (:maybe  i1)       matches zero or one of i1.
#   (:oneof  i1 i2 i3) matches any one of the items i1, i2, i3.
#   (:anyof  i1 i2 i3) matches zero or more of the items i1, i2, i3.
#   (:someof i1 i2 i3) matches one or more of i1, i2, and i3.
#
#   (:unordered i1 i2 i3) matches all of i1, i2, and i3, in any order.
#
# The matching algorithm is a stupid greedy algorithm.  If you need to
# check stuff it can't handle, write a new thing.

