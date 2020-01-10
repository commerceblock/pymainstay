# Copyright (c) 2019 CommerceBlock Team
# Use of this source code is governed by an MIT
# license that can be found in the LICENSE file.

import sys
import logging

import mst.args

def main():
    args = mst.args.parse_msc_args(sys.argv[1:])

    logging.basicConfig(format='%(message)s')

    if args.verbosity == 0:
        logging.root.setLevel(logging.INFO)
    elif args.verbosity > 0:
        logging.root.setLevel(logging.DEBUG)
    elif args.verbosity == -1:
        logging.root.setLevel(logging.WARNING)
    elif args.verbosity < -1:
        logging.root.setLevel(logging.ERROR)

    if not hasattr(args, 'cmd_func'):
        args.parser.error('No command specified')

    args.cmd_func(args)
