
import unittest
import doctest

import glider.keys
import glider.formats
import glider.tests

class EncodingTest(unittest.TestCase):
    def testQuotedString(self):
        self.assertEquals(1,1)

def suite():
    import sexp.tests
    suite = unittest.TestSuite()

    suite.addTest(doctest.DocTestSuite(glider.formats))
    suite.addTest(doctest.DocTestSuite(glider.keys))

    loader = unittest.TestLoader()
    suite.addTest(loader.loadTestsFromModule(glider.tests))

    return suite


if __name__ == '__main__':

    unittest.TextTestRunner(verbosity=1).run(suite())
