import sys
import json
import os
import random
import unittest
from io import StringIO

import mst.cmds as cm
import mst.args

class TestVerify(unittest.TestCase):

    def test_validlist(self):

        raw_args = []
        raw_args.append('verify')
        raw_args.append('-f')
        raw_args.append('test_sequence_1.msp')
        raw_args.append('-l')
        raw_args.append('2ec91e4da17e991b2b11d4de76b43fe9a550ce2a59d8b2e0c9dbebc8f5aead5a,2e93d25081d0c14cfe0d556e0c5c0e4b6b109d50e61f0caa16da33b064c3ac87,50270593506e065e127e8abfa05205337163ebdeeb1ae45428af8b02cda761c9')

        args = mst.args.parse_msc_args(raw_args)

        out = cm.verify_command(args)
        self.assertTrue(out)

    def test_unorderedlist(self):

        raw_args = []
        raw_args.append('verify')
        raw_args.append('-f')
        raw_args.append('test_sequence_1.msp')
        raw_args.append('-l')
        raw_args.append('2e93d25081d0c14cfe0d556e0c5c0e4b6b109d50e61f0caa16da33b064c3ac87,2ec91e4da17e991b2b11d4de76b43fe9a550ce2a59d8b2e0c9dbebc8f5aead5a,50270593506e065e127e8abfa05205337163ebdeeb1ae45428af8b02cda761c9')

        args = mst.args.parse_msc_args(raw_args)

        out = cm.verify_command(args)
        self.assertFalse(out)

    def test_invalidlistproof(self):

        raw_args = []
        raw_args.append('verify')
        raw_args.append('-f')
        raw_args.append('test_sequence_2.msp')
        raw_args.append('-l')
        raw_args.append('2ec91e4da17e991b2b11d4de76b43fe9a550ce2a59d8b2e0c9dbebc8f5aead5a,2e93d25081d0c14cfe0d556e0c5c0e4b6b109d50e61f0caa16da33b064c3ac87,50270593506e065e127e8abfa05205337163ebdeeb1ae45428af8b02cda761c9')

        args = mst.args.parse_msc_args(raw_args)

        out = cm.verify_command(args)
        self.assertFalse(out)

    def test_validproof(self):

        raw_args = []
        raw_args.append('verify')
        raw_args.append('-f')
        raw_args.append('test_sequence_1.msp')
        raw_args.append('-i')
        raw_args.append('5222ffe08bfd4ca0db30d261b2d54d0b6e3faed5276be422e5e6ac32c450ccd7')

        args = mst.args.parse_msc_args(raw_args)
        out = cm.verify_command(args)
        self.assertTrue(out)

    def test_invalidproof(self):

        raw_args = []
        raw_args.append('verify')
        raw_args.append('-f')
        raw_args.append('test_sequence_3.msp')

        args = mst.args.parse_msc_args(raw_args)
        try:
            out = cm.verify_command(args)
        except:
            out = False
        self.assertFalse(out)

if __name__ == '__main__': 
    unittest.main()