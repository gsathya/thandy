# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

"""This file defines an object oriented pattern matching system used to
   check decoded xJSON objects.
"""

import re
import sys

import thandy

class Schema:
    """A Schema matches a set of possible Python objects, of types
       that are encodable in JSON.  This is an abstract base type;
       see implementations below."""
    def matches(self, obj):
        """Return True if 'obj' matches this schema, False if it doesn't."""
        try:
            self.checkMatch(obj)
        except thandy.FormatException:
            return False
        else:
            return True

    def checkMatch(self, obj):
        """Raise thandy.FormatException if 'obj' does not match this schema.
           Abstract method."""
        raise NotImplemented()

class Any(Schema):
    """
       Matches any single object.

       >>> s = Any()
       >>> s.matches("A String")
       True
       >>> s.matches([1, "list"])
       True
    """
    def checkMatch(self, obj):
        pass

class RE(Schema):
    """
       Matches any string that matches a given regular expression.

       >>> s = RE("h.*d")
       >>> s.matches("hello world")
       True
       >>> s.matches("Hello World")
       False
       >>> s.matches("hello world!")
       False
       >>> s.matches([33, "Hello"])
       False
    """
    def __init__(self, pat=None, modifiers=0, reObj=None, reName=None):
        """Make a new RE schema
             pat -- The pattern to match, or None if reObj is provided.
             modifiers -- Flags to use when compiling the pattern.
             reObj -- A compiled regular expression object.
        """
        if not reObj:
            if not pat.endswith("$"):
                pat += "$"
            reObj = re.compile(pat, modifiers)
        self._re = reObj
        if reName == None:
            if pat != None:
                reName = "pattern /%s/"%pat
            else:
                reName = "pattern"
        self._reName = reName
    def checkMatch(self, obj):
        if not isinstance(obj, basestring) or not self._re.match(obj):
            raise thandy.FormatException("%r did not match %s"
                                         %(obj,self._reName))

class Str(Schema):
    """
       Matches a particular string, and no other.

       >>> s = Str("Hi")
       >>> s.matches("Hi")
       True
       >>> s.matches("Not hi")
       False
    """
    def __init__(self, val):
        self._str = val
    def checkMatch(self, obj):
        if self._str != obj:
            raise thandy.FormatException("Expected %r; got %r"%(self._str, obj))

class AnyStr(Schema):
    """
       Matches any string, but no non-string object.

       >>> s = AnyStr()
       >>> s.matches("")
       True
       >>> s.matches("a string")
       True
       >>> s.matches(["a"])
       False
       >>> s.matches(3)
       False
       >>> s.matches(u"a unicode string")
       True
       >>> s.matches({})
       False
    """
    def __init__(self):
        pass
    def checkMatch(self, obj):
        if not isinstance(obj, basestring):
            raise thandy.FormatException("Expected a string; got %r"%obj)

class OneOf(Schema):
    """
       Matches an object that matches any one of several sub-schemas.

       >>> s = OneOf([ListOf(Int()), Str("Hello"), Str("bye")])
       >>> s.matches(3)
       False
       >>> s.matches("bye")
       True
       >>> s.matches([])
       True
       >>> s.matches([1,2])
       True
       >>> s.matches(["Hi"])
       False
    """
    def __init__(self, alternatives):
        self._subschemas = alternatives

    def checkMatch(self, obj):
        for m in self._subschemas:
            if m.matches(obj):
                return

        raise thandy.FormatException("Object matched no recognized alternative")

class AllOf(Schema):
    """Matches the intersection of a list of schemas.

       >>> s = AllOf([RE(r'.*end'), RE(r'begin.*')])
       >>> s.matches("an end")
       False
       >>> s.matches("begin well")
       False
       >>> s.matches("begin and end")
       True
    """
    def __init__(self, required):
        self._subschemas = required[:]

    def checkMatch(self, obj):
        for s in self._subschemas:
            s.checkMatch(obj)

class ListOf(Schema):
    """
       Matches a homogenous list of some subschema.

       >>> s = ListOf(RE("(?:..)*"))
       >>> s.matches("hi")
       False
       >>> s.matches([])
       True
       >>> s.matches({})
       False
       >>> s.matches(["Hi", "this", "list", "is", "full", "of", "even", "strs"])
       True
       >>> s.matches(["This", "one", "is not"])
       False

       >>> s = ListOf(Int(), minCount=3, maxCount=10)
       >>> s.matches([3]*2)
       False
       >>> s.matches([3]*3)
       True
       >>> s.matches([3]*10)
       True
       >>> s.matches([3]*11)
       False
    """
    def __init__(self, schema, minCount=0, maxCount=sys.maxint,listName="list"):
        """Create a new ListOf schema to match anywhere from minCount to
           maxCount objects conforming to 'schema'.  When generating errors,
           we will call this type 'listName'.
        """
        self._schema = schema
        self._minCount = minCount
        self._maxCount = maxCount
        self._listName = listName
    def checkMatch(self, obj):
        if not isinstance(obj, (list, tuple)):
            raise thandy.FormatException("Expected %s; got %r"
                                         %(self._listName,obj))
        for item in obj:
            try:
                self._schema.checkMatch(item)
            except thandy.FormatException, e:
                raise thandy.FormatException("%s in %s"%(e, self._listName))

        if not (self._minCount <= len(obj) <= self._maxCount):
            raise thandy.FormatException("Length of %s out of range"
                                         %self._listName)

class Struct(Schema):
    """
       Matches a non-homogenous list of items.

       >>> s = Struct([ListOf(AnyStr()), AnyStr(), Str("X")])
       >>> s.matches(False)
       False
       >>> s.matches("Foo")
       False
       >>> s.matches([[], "Q", "X"])
       True
       >>> s.matches([[], "Q", "D"])
       False
       >>> s.matches([[3], "Q", "X"])
       False
       >>> s.matches([[], "Q", "X", "Y"])
       False

       >>> s = Struct([Str("X")], allowMore=True)
       >>> s.matches([])
       False
       >>> s.matches(["X"])
       True
       >>> s.matches(["X", "Y"])
       True
       >>> s.matches(["X", ["Y", "Z"]])
       True
       >>> s.matches([["X"]])
       False

       >>> s = Struct([Str("X"), Int()], [Int()])
       >>> s.matches([])
       False
       >>> s.matches({})
       False
       >>> s.matches(["X"])
       False
       >>> s.matches(["X", 3])
       True
       >>> s.matches(["X", 3, 9])
       True
       >>> s.matches(["X", 3, 9, 11])
       False
       >>> s.matches(["X", 3, "A"])
       False
    """
    def __init__(self, subschemas, optschemas=[], allowMore=False,
                 structName="list"):
        """Create a new Struct schema to match lists that begin with
           each item in 'subschemas' in order.  If there are more elements
           than items in subschemas, additional elements much match
           the items in optschemas (if any).  If there are more elements
           than items in subschemas and optschemas put together, then
           the object is only matched when allowMore is true.
        """
        self._subschemas = subschemas + optschemas
        self._min = len(subschemas)
        self._allowMore = allowMore
        self._structName = structName
    def checkMatch(self, obj):
        if not isinstance(obj, (list, tuple)):
            raise thandy.FormatException("Expected %s; got %r"
                                         %(self._structName,obj))
        elif len(obj) < self._min:
            raise thandy.FormatException(
                "Too few fields in %s"%self._structName)
        elif len(obj) > len(self._subschemas) and not self._allowMore:
            raise thandy.FormatException(
                "Too many fields in %s"%self._structName)
        for item, schema in zip(obj, self._subschemas):
            schema.checkMatch(item)

class DictOf(Schema):
    """
       Matches a mapping from items matching a particular key-schema
       to items matching a value-schema.  Note that in JSON, keys must
       be strings.

       >>> s = DictOf(RE(r'[aeiou]+'), Struct([AnyStr(), AnyStr()]))
       >>> s.matches("")
       False
       >>> s.matches({})
       True
       >>> s.matches({"a": ["x", "y"], "e" : ["", ""]})
       True
       >>> s.matches({"a": ["x", 3], "e" : ["", ""]})
       False
       >>> s.matches({"a": ["x", "y"], "e" : ["", ""], "d" : ["a", "b"]})
       False
    """
    def __init__(self, keySchema, valSchema):
        """Return a new DictSchema to match objects all of whose keys match
           keySchema, and all of whose values match valSchema."""
        self._keySchema = keySchema
        self._valSchema = valSchema
    def checkMatch(self, obj):
        try:
            iter = obj.iteritems()
        except AttributeError:
            raise thandy.FormatException("Expected a dict; got %r"%obj)

        for k,v in iter:
            self._keySchema.checkMatch(k)
            self._valSchema.checkMatch(v)

class Opt:
    """Helper; applied to a value in Obj to mark it optional.

       >>> s = Obj(k1=Str("X"), k2=Opt(Str("Y")))
       >>> s.matches({'k1': "X", 'k2': "Y"})
       True
       >>> s.matches({'k1': "X", 'k2': "Z"})
       False
       >>> s.matches({'k1': "X"})
       True
    """
    def __init__(self, schema):
        self._schema = schema
    def checkMatch(self, obj):
        self._schema.checkMatch(obj)

class Obj(Schema):
    """
       Matches a dict from specified keys to key-specific types.  All
       keys are requied unless explicitly marked with Opt.
       Unrecognized keys are always allowed.

       >>> s = Obj(a=AnyStr(), bc=Struct([Int(), Int()]))
       >>> s.matches({'a':"ZYYY", 'bc':[5,9]})
       True
       >>> s.matches({'a':"ZYYY", 'bc':[5,9], 'xx':5})
       True
       >>> s.matches({'a':"ZYYY", 'bc':[5,9,3]})
       False
       >>> s.matches({'a':"ZYYY"})
       False

    """
    def __init__(self, _objname="object", **d):
        self._objname = _objname
        self._required = d.items()

    def checkMatch(self, obj):
        if not isinstance(obj, dict):
            raise thandy.FormatException("Wanted a %s; did not get a dict"%
                                         self._objname)

        for k,schema in self._required:
            try:
                item = obj[k]
            except KeyError:
                if not isinstance(schema, Opt):
                    raise thandy.FormatException("Missing key %s in %s"
                                                 %(k,self._objname))

            else:
                try:
                    schema.checkMatch(item)
                except thandy.FormatException, e:
                    raise thandy.FormatException("%s in %s.%s"
                                                 %(e,self._objname,k))

class TaggedObj(Schema):
    """
       Matches an object based on the value of a particular 'tag' field.
       If tagIsOptional, matches any object when the tag is missing.
       If ignoreUnrecognized, matches any object when the tag is present
       but the value is not one we know.

       >>> s = TaggedObj('tp', a=Obj(int1=Int()), b=Obj(s=AnyStr()))
       >>> s.matches(3)
       False
       >>> s.matches([])
       False
       >>> s.matches({})
       False
       >>> s.matches({'tp' : 'fred'})
       True
       >>> s.matches({'tp' : 'a'})
       False
       >>> s.matches({'tp' : 'a', 'int1': 3})
       True
       >>> s.matches({'tp' : 'a', 'int1': []})
       False
       >>> s.matches({'tp' : 'b', 'int1': 3, 's': 'tt'})
       True
    """
    def __init__(self, tagName, tagIsOptional=False, ignoreUnrecognized=True,
                 **tagvals):
        #DOCDOC
        self._tagName = tagName
        self._tagOpt = tagIsOptional
        self._ignoreOthers = ignoreUnrecognized
        self._tagvals = tagvals

    def checkMatch(self, obj):
        try:
            tag = obj[self._tagName]
        except KeyError:
            if self._tagOpt:
                return
            else:
                raise thandy.FormatException("Missing tag %s on object"%
                                             self._tagName)
        except TypeError:
            raise thandy.FormatException("Got a %s, not a tagged object"%
                                         type(obj))
        if not isinstance(tag, basestring):
            raise thandy.FormatException("Expected a string for %s; got a %s"%(
                    self._tagName, type(tag)))
        try:
            subschema = self._tagvals[tag]
        except KeyError:
            if self._ignoreOthers:
                return
            else:
                raise thandy.FormatException("Unrecognized value %s for %s"%(
                        tag, self._tagName))

        subschema.checkMatch(obj)

class Int(Schema):
    """
       Matches an integer.

       >>> s = Int()
       >>> s.matches(99)
       True
       >>> s.matches(False)
       False
       >>> s.matches(0L)
       True
       >>> s.matches("a string")
       False
       >>> Int(lo=10, hi=30).matches(25)
       True
       >>> Int(lo=10, hi=30).matches(5)
       False
    """
    def __init__(self, lo=None, hi=None):
        """Return a new Int schema to match items between lo and hi inclusive.
        """
        if lo is not None and hi is not None:
            assert lo <= hi
        self._lo = lo
        self._hi = hi
        plo,phi=lo,hi
        if plo is None: plo = "..."
        if phi is None: phi = "..."
        self._range = "[%s,%s]"%(plo,phi)
    def checkMatch(self, obj):
        if isinstance(obj, bool) or not isinstance(obj, (int, long)):
            # We need to check for bool as a special case, since bool
            # is for historical reasons a subtype of int.
            raise thandy.FormatException("Got %r instead of an integer"%obj)
        elif (self._lo is not None and self._lo > obj) or (
            self._hi is not None and self._hi < obj):
            raise thandy.FormatException("%r not in range %s"
                                         %(obj, self._range))

class Bool(Schema):
    """
       Matches a boolean.

       >>> s = Bool()
       >>> s.matches(True) and s.matches(False)
       True
       >>> s.matches(11)
       False
    """
    def __init__(self):
        pass
    def checkMatch(self, obj):
        if not isinstance(obj, bool):
            raise thandy.FormatException("Got %r instead of a boolean"%obj)

class Func(Schema):
    """
       Matches an object based on the value of some boolen function

       >>> even = lambda x: (x%2)==0
       >>> s = Func(even, baseSchema=Int())
       >>> s.matches(99)
       False
       >>> s.matches(98)
       True
       >>> s.matches("ninety-eight")
       False
    """
    def __init__(self, fn, baseSchema=None):
        #DOCDOC
        self._fn = fn
        self._base = baseSchema
    def checkMatch(self, obj):
        if self._base:
            self._base.checkMatch(obj)
        r = self._fn(obj)
        if r is False:
            raise thandy.FormatException("%s returned False"%self._fn)
