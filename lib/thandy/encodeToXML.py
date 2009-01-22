# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import re
import thandy

def xml_str_encoder(s):
    s = s.replace("&", "&amp;")
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    return s

def isAsciiName(s):
    """
       Return true iff s is pure-ascii, and a syntactically valid XML name.

       >>> isAsciiName("a")
       True
       >>> isAsciiName("ab.-dc")
       True
       >>> isAsciiName("")
       False
       >>> isAsciiName(".foo")
       False
    """
    return re.match(r'^[A-Za-z\_\:][A-Za-z0-9\_\:\-\.]*$', s) != None

def _encodeToXML(obj, outf):
    if isinstance(obj, basestring):
        outf(xml_str_encoder(obj))
    elif obj is True:
        outf("true")
    elif obj is False:
        outf("false")
    elif obj is None:
        outf("null")
    elif isinstance(obj, (int,long)):
        outf(str(obj))
    elif isinstance(obj, (tuple, list)):
        outf("<list>\n")
        for item in obj:
            outf("<item>")
            _encodeToXML(item, outf)
            outf("</item> ")
        outf("</list>\n")
    elif isinstance(obj, dict):
        outf("<dict>\n")
        for k,v in sorted(obj.items()):
            isAscii = isAsciiName(k)
            if isAscii:
                outf("<%s>"%k)
                _encodeToXML(v, outf)
                outf("</%s>\n"%k)
            else:
                outf("<dict-entry><key>%s</key><val>"%xml_str_encoder(k))
                _encodeToXML(v, outf)
                outf("</val></dict-entry>\n")
        outf("</dict>\n")
    else:
        raise thandy.FormatException("I can't encode %r"%obj)

def encodeToXML(obj, outf=None):
    """Convert a json-encodable object to a quick-and-dirty XML equivalent."""
    result = None
    if outf == None:
        result = []
        outf = result.append

    _encodeToXML(obj, outf)
    if result is not None:
        return "".join(result)

