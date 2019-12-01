import sys
import json
import os
import random
import unittest
from io import StringIO

import mst.ecc
import mst.cmds as cm
import mst.args

class TestECC(unittest.TestCase):

    def test_pubkey(self):
        privkey = 'a324f680ee30a57a5df3c5ad52f790f4bc153b95ef7c237ff53d6f8a739470cc'
        pubkey = '02fbbccc7d6eba14afb648ce68cac3776d37f2b16355647e981bd12eeb984c86e6'

        raw_args = []
        raw_args.append('keygen')
        raw_args.append('-p')
        raw_args.append(privkey)

        args = mst.args.parse_msc_args(raw_args)

        out = cm.keygen_command(args)
        self.assertEqual(pubkey, out)

    def test_signature(self):
        privkey = 'a324f680ee30a57a5df3c5ad52f790f4bc153b95ef7c237ff53d6f8a739470cc'
        commit = 'fbbccc7d6eba14afb648ce68cac3776d37f2b16355647e981bd12eeb984c86e6'
        sig = 'MEUCIQCIUbLVubvbVM2izpETWY9ZaNYAmfEZd0rdDnzYnvVnkwIgDu2hQCrMfyBoVdFd8xta8KulNzCNmrCip2veMyDLb+0='

        raw_args = []
        raw_args.append('keygen')
        raw_args.append('-s')
        raw_args.append(commit)

        args = mst.args.parse_msc_args(raw_args)

        out = cm.keygen_command(args)
        self.assertEqual(sig, out)

if __name__ == '__main__': 
    unittest.main()