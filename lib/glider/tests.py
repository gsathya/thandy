
import unittest
import doctest
import os
import tempfile

import glider.keys
import glider.formats
import glider.repository
import glider.checkJson

import glider.tests

class CanonicalEncodingTest(unittest.TestCase):
    def test_encode(self):
        enc = glider.formats.encodeCanonical
        self.assertEquals(enc(''), '""')
        self.assertEquals(enc('"'), '"\\""')
        self.assertEquals(enc('\t\\\n"\r'),
                          '"\t\\\\\n\\"\r"')

class CryptoTests(unittest.TestCase):
    def test_encrypt(self):
        s = "The Secret words are marzipan habidashery zeugma."
        password = "the password is swordfish."
        encrypted = glider.keys.encryptSecret(s, password)
        self.assertNotEquals(encrypted, s)
        self.assert_(encrypted.startswith("GKEY1"))
        self.assertEquals(s, glider.keys.decryptSecret(encrypted, password))
        self.assertRaises(glider.BadPassword, glider.keys.decryptSecret,
                          encrypted, "password")
        self.assertRaises(glider.UnknownFormat, glider.keys.decryptSecret,
                          "foobar", password)

    def test_keystore(self):
        passwd = "umfitty noonah"
        fname = tempfile.mktemp()
        ks = glider.keys.KeyStore(fname)
        key1 = glider.keys.RSAKey.generate(512)
        key2 = glider.keys.RSAKey.generate(512)
        ks.addKey(key1)
        ks.addKey(key2)
        ks.save(passwd)

        ks2 = glider.keys.KeyStore(fname)
        ks2.load(passwd)
        self.assertEquals(key1.key.n, ks2.getKey(key1.getKeyID()).key.n)

def suite():
    suite = unittest.TestSuite()

    suite.addTest(doctest.DocTestSuite(glider.formats))
    suite.addTest(doctest.DocTestSuite(glider.keys))
    suite.addTest(doctest.DocTestSuite(glider.checkJson))

    loader = unittest.TestLoader()
    suite.addTest(loader.loadTestsFromModule(glider.tests))

    return suite


if __name__ == '__main__':

    unittest.TextTestRunner(verbosity=1).run(suite())
