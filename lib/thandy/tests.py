# Copyright 2008 The Tor Project, Inc.  See LICENSE for licensing information.

import unittest
import doctest
import os
import tempfile

import thandy.keys
import thandy.formats
import thandy.repository
import thandy.checkJson
import thandy.encodeToXML
import thandy.util
import thandy.packagesys
import thandy.packagesys.PackageSystem
import thandy.packagesys.PackageDB
import thandy.packagesys.RPMPackages
import thandy.packagesys.ExePackages

import thandy.tests

def deltree(top):
    for dirpath, dirnames, filenames in os.walk(top, topdown=False):
        for f in filenames:
            os.unlink(os.path.join(dirpath, f))
        for d in dirnames:
            os.rmdir(os.path.join(dirpath, d))
    os.rmdir(top)

def contents(fn, mode='rb'):
    f = open(fn, mode)
    try:
        return f.read()
    finally:
        f.close()

class CanonicalEncodingTest(unittest.TestCase):
    def test_encode(self):
        enc = thandy.formats.encodeCanonical
        self.assertEquals(enc(''), '""')
        self.assertEquals(enc('"'), '"\\""')
        self.assertEquals(enc('\t\\\n"\r'),
                          '"\t\\\\\n\\"\r"')

class CryptoTests(unittest.TestCase):
    def test_encrypt(self):
        s = "The Secret words are marzipan habidashery zeugma."
        password = "the password is swordfish."
        encrypted = thandy.keys.encryptSecret(s, password)
        self.assertNotEquals(encrypted, s)
        self.assert_(encrypted.startswith("GKEY1"))
        self.assertEquals(s, thandy.keys.decryptSecret(encrypted, password))
        self.assertRaises(thandy.BadPassword, thandy.keys.decryptSecret,
                          encrypted, "password")
        self.assertRaises(thandy.UnknownFormat, thandy.keys.decryptSecret,
                          "foobar", password)

    def test_keystore(self):
        passwd = "umfitty noonah"
        fname = tempfile.mktemp()
        ks = thandy.keys.KeyStore(fname)
        key1 = thandy.keys.RSAKey.generate(512)
        key2 = thandy.keys.RSAKey.generate(512)
        ks.addKey(key1)
        ks.addKey(key2)
        ks.save(passwd)

        ks2 = thandy.keys.KeyStore(fname)
        ks2.load(passwd)
        self.assertEquals(key1.key.n, ks2.getKey(key1.getKeyID()).key.n)

class UtilTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp()
    def tearDown(self):
        deltree(self._dir)

    def test_replaceFile(self):
        fn1 = os.path.join(self._dir, "File1")
        S1="Why do you curtsey, commoner? I presumed this would be anonymous."
        S2="I am simply guaranteeing your commitment to my anonymity."
        # -- WIGU adventures, 24 March 2005.
        thandy.util.replaceFile(fn1, S1)
        self.assertEquals(contents(fn1), S1)
        thandy.util.replaceFile(fn1, S2)
        self.assertEquals(contents(fn1), S2)

        self.assertEquals(os.listdir(self._dir), [ "File1" ])

    def test_moveFile(self):
        d = self._dir
        os.mkdir(os.path.join(d, "subdir"))
        fn1 = os.path.join(d, "f1")
        fn2 = os.path.join(d, "f2")
        fn3 = os.path.join(d, "subdir", "f3")
        S1="""We monitor all citizens constantly to detect insider baddies!
              Isn't it wondersome?!"""
        S2="""Wondersome yes... But could such a tactic instill a sense of
              distrust and fear in a populace that is overwhelmingly true and
              pious?"""
        S3="""I think the fact that we are not currently under siege by
              unscrupulous minions speaks for itself."""
        # -- WIGU adventures, 22 January 2004

        thandy.util.replaceFile(fn1, S1)
        thandy.util.replaceFile(fn2, S2)
        thandy.util.replaceFile(fn3, S3)

        self.assertEquals(contents(fn1), S1)
        self.assertTrue(os.path.exists(fn2))
        self.assertTrue(os.path.exists(fn3))

        thandy.util.moveFile(fn2, fn1)
        self.assertEquals(contents(fn1), S2)
        self.assertFalse(os.path.exists(fn2))

        thandy.util.moveFile(fn1, fn3)
        self.assertEquals(contents(fn3), S2)
        self.assertFalse(os.path.exists(fn1))

        self.assertEquals(os.listdir(d), ["subdir"])
        self.assertEquals(os.listdir(os.path.join(d, "subdir")), ["f3"])


def suite():
    suite = unittest.TestSuite()

    suite.addTest(doctest.DocTestSuite(thandy.formats))
    suite.addTest(doctest.DocTestSuite(thandy.keys))
    suite.addTest(doctest.DocTestSuite(thandy.checkJson))
    suite.addTest(doctest.DocTestSuite(thandy.encodeToXML))

    loader = unittest.TestLoader()
    suite.addTest(loader.loadTestsFromModule(thandy.tests))

    return suite


if __name__ == '__main__':

    unittest.TextTestRunner(verbosity=1).run(suite())
