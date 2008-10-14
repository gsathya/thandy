#!/usr/bin/python
# Copyright 2008 The Tor Project.  See LICENSE for licensing information.
# $Id: setup.py,v 1.103 2007-09-15 19:06:37 nickm Exp $

import sys

#
#   Current Thandy version
#
VERSION = '0.0.1-alpha'
# System: 0==alpha, 50==beta, 98=pre, 99==release candidate, 100==release
VERSION_INFO = (0,0,1)

for name in [ "simplejson", "Crypto" ]:
    try:
        __import__(name)
    except ImportError:
        print "Missing support for module %s"%name
        sys.exit(1)

import os, re, shutil, string, struct, sys

os.umask(022)

#======================================================================
# Create startup scripts if we're installing.

if not os.path.isdir("./bin"):
    os.mkdir("./bin")

SCRIPTS = []

def makescripts(extrapath=None):
    del SCRIPTS[:]
    for script_suffix, modname in [ ("server", "ServerCLI"),
                                    ("client", "ClientCLI"),
                                    ("pk", "SignerCLI"), ]:
        fname = os.path.join("./bin", "thandy-%s"%script_suffix)
        if sys.platform == "win32":
            fname += ".py"
        f = open(fname, 'w')
        f.write("#!/bin/sh\n")
        if extrapath:
            f.write('PYTHONPATH="$PYTHONPATH:%s"\n'%extrapath)
            f.write('export PYTHONPATH\n')
        f.write('%s -m thandy.%s "$@"\n' %(sys.executable, modname))
        f.close()
        SCRIPTS.append(fname)

#======================================================================
# Define a helper to let us run commands from the compiled code.
def _haveCmd(cmdname):
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if os.path.exists(os.path.join(entry, cmdname)):
            return 1
    return 0

def requirePythonDev(e=None):
    if os.path.exists("/etc/debian_version"):
        v = sys.version[:3]
        print "Debian may expect you to install python%s-dev"%v
    elif os.path.exists("/etc/redhat-release"):
        print "Redhat may expect you to install python2-devel"
    else:
        print "You may be missing some 'python development' package for your"
        print "distribution."

    if e:
        print "(Error was: %s)"%e

    sys.exit(1)

try:
    from distutils.core import Command
    from distutils.errors import DistutilsPlatformError
    from distutils.sysconfig import get_makefile_filename
except ImportError, e:
    print "\nUh oh. You have Python installed, but I didn't find the distutils"
    print "module, which is supposed to come with the standard library.\n"

    requirePythonDev()

try:
    # This catches failures to install python2-dev on some redhats.
    get_makefile_filename()
except IOError:
    print "\nUh oh. You have Python installed, but distutils can't find the"
    print "Makefile it needs to build additional Python components.\n"

    requirePythonDev()

#======================================================================
# Now, tell setup.py how to cope.
import distutils.core, distutils.command.install
from distutils.core import setup, Distribution

class InstallCommand(distutils.command.install.install):
    def run(self):
        script_path = None
        sys_path = map(os.path.normpath, sys.path)
        sys_path = map(os.path.normcase, sys_path)
        install_lib = os.path.normcase(os.path.normpath(self.install_lib))

        if install_lib not in sys_path:
            script_path = install_lib

        makescripts(self.install_lib)

        distutils.command.install.install.run(self)

setup(name='Thandy',
      version=VERSION,
      license="3-clause BSD",
      description=
      "Thandy: Secure cross-platform update automation tool.",
      author="Nick Mathewson",
      author_email="nickm@freehaven.net",
      url="http://www.torproject/org",
      package_dir={ '' : 'lib' },
      packages=['thandy'],
      scripts=SCRIPTS,
      cmdclass={'install': InstallCommand},
)

