
import unittest
import doctest
import os
import tempfile

import thandy.keys
import thandy.formats
import thandy.repository
import thandy.checkJson

import thandy.tests

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

def suite():
    suite = unittest.TestSuite()

    suite.addTest(doctest.DocTestSuite(thandy.formats))
    suite.addTest(doctest.DocTestSuite(thandy.keys))
    suite.addTest(doctest.DocTestSuite(thandy.checkJson))

    loader = unittest.TestLoader()
    suite.addTest(loader.loadTestsFromModule(thandy.tests))

    return suite


if __name__ == '__main__':

    unittest.TextTestRunner(verbosity=1).run(suite())
