
import re
import sys

def s_tag(s):
    """Returns the tag of an s-expression (that is, the string that is its
       first element), or None of the expression has no tag.

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
    """Return the fist child of 's' whose tag is 'tag', or None if no such
       child exists.

    >>> x = [ 'example', ['greeting', 'hello'], [ 'world', 'earth'] ]
    >>> s_child(x, "greeting")
    ['greeting', 'hello']
    >>> s_child(x, "world")
    ['world', 'earth']
    >>> print s_child(x, "foo")
    None
    """

    for child in s:
        if s_tag(child) == tag:
            return child
    return None

def s_attr(s, tag):
    """Returns the second element of the child of 's' whose tag is 'tag'.
       This is helpful for extracting a (key val) element.  Returns None
       if there is no such element.
    """
    ch = s_child(s,tag)
    if ch == None or len(ch) < 2:
        return None
    return ch[1]

def s_children(s, tag):
    """Returns a generator yielding all children of 's' whose tag is 'tag'.

    >>> x = [ ['quark', 'top'], ['cheese', 'stilton'], ['quark', 'bottom'],
    ...       ['cheese', 'cheddar'], "cheese" ]
    >>> list(s_children(x, "Foo"))
    []
    >>> list(s_children(x, "cheese"))
    [['cheese', 'stilton'], ['cheese', 'cheddar']]
    """
    return (ch for ch in s if s_tag(ch) == tag)

def s_descendants(s, tags=()):
    """Yield every descendant of 's' whose tag is in 'tags'.  If 'tags' is
       false, yield every descendant of s.  Items are returned in depth-first
       order.

    >>> x = [ 'foo', ['bar', ['foo', 'quuz'], ['foo', ['foo', 'zilch']] ],
    ...      ['foo', 'quum'], ['mulch', 'mulchy', 'foo', ['foo', 'baaz']]]
    >>> list(s_descendants(x, ['mulch']))
    [['mulch', 'mulchy', 'foo', ['foo', 'baaz']]]
    >>> for item in s_descendants(x, ['foo']): print item
    ['foo', 'quuz']
    ['foo', ['foo', 'zilch']]
    ['foo', 'zilch']
    ['foo', 'quum']
    ['foo', 'baaz']
    >>> x = ['a', 'b', 'c', ['d', ['e', 'f']], ['g']]
    >>> list(s_descendants(x))
    [['d', ['e', 'f']], ['e', 'f'], ['g']]
    """
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
        if not tags or s_tag(s[idx]) in tags:
            yield s[idx]
        push((s, idx+1))
        s = s[idx]
        idx = 0

def attrs_to_dict(sexpr):
    """Return a dictionary mapping keys of the attributes in sexpr to
       their values.  Only the last element in the attribute list counts.

    >>> s = [ 'given-name',
    ...      ["Tigra", 'Rachel'], ["Bunny", "Elana"] ]
    >>> attrs_to_dict(s)
    {'Tigra': ['Rachel'], 'Bunny': ['Elana']}
    """
    result = {}
    for ch in sexpr:
        tag = s_tag(ch)
        if tag is not None:
            result[tag]=ch[1:]
    return result

class SExpr(list):
    """Wraps an s-expresion list to return its tagged children as attributes.

    >>> s = [ 'cat', ['cheezburger', 'can has'], ['laser', 'can not has'],
    ...       ['adjectives', ['furry', 'yes'], ['nuclear', 'no']]]
    >>> s = SExpr(s)
    >>> s[0]
    'cat'
    >>> s_tag(s)
    'cat'
    >>> s.cheezburger
    ['cheezburger', 'can has']
    >>> s.cheezburger  # Check caching.
    ['cheezburger', 'can has']
    >>> s.adjectives.furry
    ['furry', 'yes']
    >>> s.adjectives.nuclear
    ['nuclear', 'no']
    >>> s.do_not_want
    Traceback (most recent call last):
    ...
    AttributeError: do_not_want
    """

    def __init__(self, stuff=()):
        list.__init__(self, stuff)
        self._d = None

    def __getattr__(self, item):
        if self._d is None: self._buildDict()
        try:
            idx = self._d[item]
        except KeyError:
            raise AttributeError(item)
        return self[idx]

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
                    _s_lookup_all(ch, path[p_idx+1:], callback)
            return
        elif p_item == '**':
            for ch in s_descendants(s):
                if not isinstance(ch, str):
                    _s_lookup_all(ch, path[p_idx+1:], callback)
            return
        elif p_item.startswith('**'):
            for ch in s_descendants(s):
                if s_tag(ch) == p_item[2:]:
                    _s_lookup_all(ch, path[p_idx+1:], callback)
        else:
            for ch in s_children(s, p_item):
                _s_lookup_all(ch, path[p_idx+1:], callback)
            return

    callback(s)

def s_lookup_all(s, path):
    """Path-based lookup.  "*" matches any single element; "**" matches all
       descendants.  Not too efficient.

    >>> x = ['alice',
    ...           ['father', 'bob', ['mother', 'carol'], ['father', 'dave']],
    ...           ['mother', 'eve', ['mother', 'frances', ['dog', 'spot']],
    ...                             ['father', 'gill']],
    ...           ['marmoset', 'tiffany'],
    ...           ['marmoset', 'gilbert']  ]
    >>> s_lookup_all(x, "father")
    [['father', 'bob', ['mother', 'carol'], ['father', 'dave']]]
    >>> s_lookup_all(x, "father.mother")
    [['mother', 'carol']]
    >>> s_lookup_all(x, "*.mother")
    [['mother', 'carol'], ['mother', 'frances', ['dog', 'spot']]]
    >>> s_lookup_all(x, "**.dog")
    [['dog', 'spot']]
    >>> s_lookup_all(x, "**mother.dog")
    [['dog', 'spot']]
    >>> s_lookup_all(x, "mother.*.dog")
    [['dog', 'spot']]
    >>> s_lookup_all(x, "marmoset")
    [['marmoset', 'tiffany'], ['marmoset', 'gilbert']]
    """
    result = []
    _s_lookup_all(s, path, result.append)
    return result

def s_lookup(s, path):
    r = s_lookup_all(s, path)
    if len(r):
        return r[0]
    return None

### Schema objects. You shouldn't instantiate these by hand; use
### parseSchema instead.

class Schema:
    """A schema represents a pattern to be applied to s-expressions.
       Generate them with parseSchema.
    """
    def matches(self, s):
        """Return true iff s matches this schema."""
        raise NotImplemented()
    def rep(self):
        """Return the s-expression representing this schema."""
        raise NotImplemented()

class _Singleton(Schema):
    '''superclass for all schemas that represent a single string or list.'''
    def isSingleton(self):
        return True

    def clear(self):
        '''used during parsing.  resets this schema to an
           I-have-matched-nothing state. '''
        self._got = False
    def matchItem(self, item):
        '''used during parsing.  Returns true iff this schema can consume
           item in its current state.'''
        if not self._got and self.matches(item):
            self._got = True
            return True
        else:
            return False
    def isSatisfied(self):
        '''used during parsing.  Returns true iff this schema would be
           satisfied parsing no more items.'''
        return self._got

class _Span(Schema):
    '''superclass for all schemas that represent a variable number of strings
       or lists.'''
    def isSingleton(self):
        return False
    def clear(self):
        pass
    def matchItem(self, item):
        raise NotImplemented()
    def isSatisfied(self):
        raise NotImplemented()

class _AnyItem(_Singleton):
    'schema representing any item'
    def matches(self,item):
        return True
    def rep(self):
        return "?"
class _AnyString(_Singleton):
    'schema representing any single string'
    def matches(self,item):
        return isinstance(item, str)
    def rep(self):
        return "."
class _ExactString(_Singleton):
    'schema that matches only a particular string'
    def __init__(self, s):
        self._s = s
    def matches(self, item):
        return item == self._s
    def rep(self):
        return "=%s"%self._s
class _ReString(_Singleton):
    'schema that matches all strings following a particular regex.'
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
    'schema that matches any list whose items match a sequence of schemas'
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
    '''schema matching any number of any items'''
    def matchItem(self, item):
        return True
    def isSatisfied(self):
        return True
    def rep(self):
        return "_"

class _NMatches(_Span):
    'schema matching another schema a given number of times.'
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
    '''schema containing a number of subitems, all of which must match in
       some order.'''
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

def parseSchema(s, table=None):
    """Return a schema object to represent a possible set of s-expressions.
       The syntax is:
        "=string" matches a string itself.
        "*" matches any number of items and can occur only at the end of a list.
        "_" matches a single item.
        "." matches any string.
        "/re/" matches a regex.
        ".name" matches a named schema stored in the map 'table'.

        (i1 i2 i3)         matches a list of i1 followed by i2 followed by i3.

        (:maybe  i1)       matches zero or one of i1.
        (:oneof  i1 i2 i3) matches any one of the items i1, i2, i3.
        (:anyof  i1 i2 i3) matches zero or more of the items i1, i2, i3.
        (:someof i1 i2 i3) matches one or more of i1, i2, and i3.

        (:unordered i1 i2 i3) matches all of i1, i2, and i3, in any order.

        The matching algorithm is a stupid greedy algorithm.  If you need to
        check stuff it can't handle, write a new thing.

    >>> import sexp.parse
    >>> P = sexp.parse.parse
    >>> PS = lambda s: parseSchema(sexp.parse.parse(s))
    >>> S1 = PS("(=hello _ . /.*geuse/)")
    >>> S1.matches(P("(hello (my little) 11:friend from Betelgeuse)"))
    True
    >>> S1.matches(P("(hello (my little) (friend from) Betelgeuse)"))
    False
    >>> S1.matches(P("(hello (my little) 11:friend from Betelgeuse Prime)"))
    False
    >>> S1.matches(P("(hello (my little) friendfrom BetelgeusePrime)"))
    False

    >>> S2 = PS("(=greetings (:oneof =world =gentlebeings) *)")
    >>> S2.matches(P("greetings"))
    False
    >>> S2.matches(P("(greetings gentlebeings)"))
    True
    >>> S2.matches(P("(greetings world please take us to (your leader))"))
    True
    """
    if isinstance(s, str):
        if not len(s):
            raise SchemaFormatError("Empty string encountered")
        if s == '*':
            return _AnyItems()
        elif s == '_':
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

