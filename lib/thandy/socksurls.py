# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

"""Implements URL types for socks-mediated connections."""

import socket
import httplib
import logging
import struct
import urllib2

# XXXX This isn't really threadsafe, but for now we don't change this after
# startup.
SOCKS_HOST = None
SOCKS_PORT = None

def setSocksProxy(host, port):
    """Set the global SOCKS proxy to host:port."""
    global SOCKS_HOST, SOCKS_PORT
    SOCKS_HOST = host
    SOCKS_PORT = port

def _recvall(sock, n):
    """Helper: fetch N bytes from the socket sock."""
    result = ""
    while 1:
        s = sock.recv(n)
        if not s:
            return result
        result += s
        n -= len(s)
        if n <= 0:
            return result

def socks_connect(host, port):
    """Helper: use the SOCKS proxy to open a connection to host:port.
       Uses the simple and Tor-friendly SOCKS4a protocol."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        logging.debug("Connecting to SOCKS proxy")
        sock.connect((SOCKS_HOST, SOCKS_PORT))

        # Now, the handshake!  We just do socks4a, since that's the simplest.
        version = 4 # socks 4
        command = 1 # connect
        addr    = 1   # 0.0.0.1, signals socks4a.
        userid  = ""

        messageheader = struct.pack("!BBHL", version, command, port, addr)
        message = "%s%s\x00%s\x00" % (messageheader, userid, host)

        sock.sendall(message)

        logging.debug("Waiting for reply from SOCKS proxy")
        reply = _recvall(sock, 8)
        code = ord(reply[1])
        if code == 0x5a:
            logging.debug("SOCKS proxy is connected.")
            return sock
        else:
            raise socket.error("Bad SOCKS response code from proxy: %d", code)
    except:
        sock.close()
        raise

# Copies of HTTPConnection and HTTPSConnection that use socks instead of
# direct connections.
class SocksHTTPConnection(httplib.HTTPConnection):
    def connect(self):
        self.sock = socks_connect(self.host, self.port)
class SocksHTTPSConnection(httplib.HTTPSConnection):
    def connect(self):
        socket = socks_connect(self.host, self.port)
        ssl = socket.ssl(sock, None, None)
        self.sock = socket.FakeSocket(socket, ssl)

# URL handlers for HTTP and HTTPS urls that use socks instead of direct
# connections.
class SocksHTTPHandler(urllib2.AbstractHTTPHandler):
    def http_open(self, req):
        return self.do_open(SocksHTTPConnection, req)
    http_request = urllib2.AbstractHTTPHandler.do_request_
class SocksHTTPSHandler(urllib2.AbstractHTTPHandler):
    def https_open(self, req):
        return self.do_open(SocksHTTPSConnection, req)
    https_request = urllib2.AbstractHTTPHandler.do_request_

def build_socks_opener():
    """Return an urllib2.OpenerDirector object to open HTTP and HTTPS
       urls using SOCKS connections."""
    opener = urllib2.OpenerDirector()
    opener.add_handler(SocksHTTPSHandler())
    opener.add_handler(SocksHTTPHandler())
    return opener
