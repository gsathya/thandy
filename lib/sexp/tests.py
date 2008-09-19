
import unittest
import doctest

import sexp.parse
import sexp.access
import sexp.encode

class EncodingTest(unittest.TestCase):
    def testQuotedString(self):
        self.assertEquals(1,1)


def suite():
    import sexp.tests
    suite = unittest.TestSuite()

    suite.addTest(doctest.DocTestSuite(sexp.encode))
    suite.addTest(doctest.DocTestSuite(sexp.parse))
    suite.addTest(doctest.DocTestSuite(sexp.access))

    loader = unittest.TestLoader()
    suite.addTest(loader.loadTestsFromModule(sexp.tests))

    return suite


if __name__ == '__main__':

    unittest.TextTestRunner(verbosity=1).run(suite())
