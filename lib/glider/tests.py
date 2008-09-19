
import unittest
import doctest

import glider.keys
import glider.formats
import glider.repository

import glider.tests

class EncryptionTest(unittest.TestCase):
    pass

def suite():
    suite = unittest.TestSuite()

    suite.addTest(doctest.DocTestSuite(glider.formats))
    suite.addTest(doctest.DocTestSuite(glider.keys))

    loader = unittest.TestLoader()
    suite.addTest(loader.loadTestsFromModule(glider.tests))

    return suite


if __name__ == '__main__':

    unittest.TextTestRunner(verbosity=1).run(suite())
