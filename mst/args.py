# Copyright (c) 2019 CommerceBlock Team
# Use of this source code is governed by an MIT
# license that can be found in the LICENSE file.

import sys
import os
import argparse
import logging

import mst
import mst.cmds

def parse_msc_args(raw_args):

    parser = argparse.ArgumentParser(description="Mainstay client")

    parser.add_argument("-q", "--quiet", action="count", default=0,
                        help="Be more quiet.")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Be more verbose. Both -v and -q may be used multiple times.")

    subparsers = parser.add_subparsers(title='Commands',
                                       description='Mainstay operations are performed via commands:')

    # Perform attestation
    parser_attest = subparsers.add_parser('attest', aliases=['a'],
                        help='Commit data to a Mainstay slot')

    attest_group  = parser_attest.add_mutually_exclusive_group()

    attest_group.add_argument('-f', '--file', type=str,
                              dest='filename',
                              help="Attest the SHA256 hash of the specified file.")

    attest_group.add_argument("-c","--commit", type=str,
                              dest='commitment',
                              help="Hex string of the 32 bytes commitment.")

    attest_group.add_argument("-g","--git", type=str,
                              dest='git',
                              help="Attest the HEAD of the specified Git repository. If 0 use stored path.")

    attest_group.add_argument("-d","--dir", type=str,
                              dest='directory',
                              help="Attest the state of the specified sequence directory.")

    parser_attest.add_argument("-s", "--slot", type=int, default=0,
                              dest='slot',
                              help="Specify the slot position index.")

    parser_attest.add_argument("--url", type=str,
                              dest='service_url',
                              default="https://mainstay.xyz",
                              help="URL for the Mainstay connector service. Default: %(default)s")

    parser_attest.add_argument("-t","--token", type=str,
                              dest='api_token',
                              default="",
                              help="API token for the specified slot position.")

    parser_attest.add_argument("-k","--privkey", type=str,
                              dest='privkey',
                              default="",
                              help="Private key for signing the commitment.")

    # Fetch proofs
    parser_fetch = subparsers.add_parser('fetch', aliases=['f'],
                              help='Fetch proofs from the Mainstay service')

    parser_fetch.add_argument('-f', '--file', type=str,
                              dest='filename',
                              help="Write proofs to specified file.")

    parser_fetch.add_argument('-o', '--output', type=str,
                              dest='output',
                              help="Write proofs to standard output.")

    parser_fetch.add_argument("-s", "--slot", type=int, default=0,
                              dest='slot',
                              help="Specify the slot position index")

    parser_fetch.add_argument("--url", type=str,
                              dest='service_url',
                              default="https://mainstay.xyz",
                              help="URL for the Mainstay connector service. Default: %(default)s")

    type_group  = parser_fetch.add_mutually_exclusive_group()

    type_group.add_argument("-c","--commit", type=str,
                              dest='commitment',
                              help="Hex string of the commitment for a single slot proof. If 0, the latest proof will be fetched.")

    type_group.add_argument("-l","--list", type=str,
                              dest='list',
                              help="Fetch proofs for a list of comma separated commitments. ")

    type_group.add_argument("-i","--txid", type=str,
                              dest='txid',
                              help="Fetch proof sequence from the latest to the specified staychain TxID. If 0, the proof will go back to the start of the slot.")

    type_group.add_argument("-u","--update", action='store_true', default=False,
                              dest='update',
                              help="Update stored proof sequence to include latest slot proofs. ")

    type_group.add_argument("-g","--git", type=str,
                              dest='gitpath',
                              help="Fetch proof sequence for specified Git repository.")
   
    # Verify proofs
    parser_verify = subparsers.add_parser('verify', aliases=['v'],
                              help='Verify Mainstay proofs against the Bitcoin blockchain')

    verify_group  = parser_verify.add_mutually_exclusive_group()

    verify_group.add_argument('-f', '--file', type=str,
                              dest='filename',
                              help="Verify the given sequence proof in the supplied file.")

    verify_group.add_argument("-c","--commit", type=str,
                              dest='commitment',
                              help="Verify the attestation of a given commitment hex and return block details")

    verify_group.add_argument("-p","--proof", type=str,
                              dest='proof',
                              help="Verify the given sequence proof (as a JSON object). If 0, a stored proof is verified.")

    parser_verify.add_argument("-b","--bitcoin-node", dest="bitcoin_node", type=str,
                              default="https://api.blockcypher.com/v1/btc/main/txs/",
                              help="Bitcoin node URL to connect to to retrieve transaction data. RPC Format: RPC_USER:RPC_PASS@RPC_HOST:RPC_PORT")

    parser_verify.add_argument("--url", type=str,
                              dest='service_url',
                              default="https://mainstay.xyz",
                              help="URL for the Mainstay connector service. Default: %(default)s")

    parser_verify.add_argument("-s", "--slot", type=int, default=0,
                              dest='slot',
                              help="Specify the slot position index for verification")

    parser_verify.add_argument("-i","--txid", type=str,
                              dest='txid',
                              help="Verify that the proof sequence is committed to the staychain containing TxID")

    list_group  = parser_verify.add_mutually_exclusive_group()

    list_group.add_argument("-l","--list", type=str,
                              dest='list',
                              help="Verify the list of comma separated commitments against the sequence proof")

    list_group.add_argument("-g","--git", type=str,
                              dest='gitpath',
                              help="Verify the sequence proof against the specified Git repository path. If 0, stored path used.")

    list_group.add_argument("-d","--dir", type=str,
                              dest='directory',
                              help="Verify the sequence proof against the time ordered files in the specified directory (path).")

    # Sync with sidechain
    parser_sync = subparsers.add_parser('sync', aliases=['s'],
                              help='Syncronise sidechain to Bitcoin via a sequence proof')

    parser_sync.add_argument("--url", type=str,
                              dest='service_url',
                              default="https://mainstay.xyz",
                              help="URL for the Mainstay connector service. Default: %(default)s")

    parser_sync.add_argument("-s", "--slot", type=int, default=0,
                              dest='slot',
                              help="Specify the slot position index (override sidechain commitment)")

    parser_sync.add_argument('-f', '--file', type=str,
                              dest='filename',
                              help="Write the sequence proof to file. ")

    parser_sync.add_argument("-b","--bitcoin-node", dest="bitcoin_node", type=str,
                              help="Bitcoin node URL to connect to and RPC details. Format: RPC_USER:RPC_PASS@RPC_HOST:RPC_PORT")

    parser_sync.add_argument("-n","--sidechain-node", dest="sidechain_node", type=str,
                              help="Sidechain node URL to connect to and RPC details. Format: RPC_USER:RPC_PASS@RPC_HOST:RPC_PORT")

    # Set config
    parser_config = subparsers.add_parser('config', aliases=['c'],
                              help='Set configuration')

    parser_config.add_argument("--url", type=str,
                              dest='service_url',
                              default="https://mainstay.xyz",
                              help="URL for the Mainstay connector service. Default: %(default)s")

    parser_config.add_argument("-s", "--slot", type=int, default=0,
                              dest='slot',
                              help="Specify the slot position index")

    parser_config.add_argument("-i","--txid", type=str,
                              dest='txid',
                              help="Specify the staychain base TxID")    

    parser_config.add_argument("-b","--bitcoin-node", dest="bitcoin_node", type=str,
                              help="Bitcoin node URL to connect to and RPC details. Format: RPC_USER:RPC_PASS@RPC_HOST:RPC_PORT")

    parser_config.add_argument("-n","--sidechain-node", dest="sidechain_node", type=str,
                              help="Sidechain node URL to connect to and RPC details. Format: RPC_USER:RPC_PASS@RPC_HOST:RPC_PORT")

    parser_config.add_argument("-t","--token", type=str,
                              dest='api_token',
                              help="API token for the specified slot position.")

    parser_config.add_argument("-k","--privkey", type=str,
                              dest='privkey',
                              help="Private key for signing the commitment.")

    parser_config.add_argument("-g","--git", type=str,
                              dest='gitpath',
                              help="Path to linked Git repository.")

    parser_config.add_argument("-d","--dir", type=str,
                              dest='directory',
                              help="Path to linked file history directory.")

    # key generation
    parser_keygen = subparsers.add_parser('keygen', aliases=['k'],
                              help='Generate signing keys for attestations')

    

    keygen_group  = parser_keygen.add_mutually_exclusive_group()

    keygen_group.add_argument("-g", "--generate", type=str,
                              dest='gen',
                              help="Generate new random private key with supplied entropy (0 will use time and system entropy only)")

    keygen_group.add_argument("-p", "--public", type=str,
                              dest='public',
                              help="Calculate the secp256k1 EC public key from the supplied hex private key.")

    keygen_group.add_argument("-s", "--sign", type=str,
                              dest='sign',
                              help="Produce a DER encoded ECDSA signature for the supplied commitment.")    

    # status and info
    parser_info = subparsers.add_parser('info', aliases=['i'],
                              help='Mainstay service status information')

    parser_info.add_argument("-s", "--slot", type=int, default=0,
                              dest='slot',
                              help="Specify the slot position index")

    parser_info.add_argument("--url", type=str,
                              dest='service_url',
                              default="https://mainstay.xyz",
                              help="URL for the Mainstay connector service. Default: %(default)s")

    parser_info.add_argument("-c", "--config",
                              dest='config',
                              help="Set the staychain base TxID in the config.")

    parser_attest.set_defaults(cmd_func=mst.cmds.attest_command)
    parser_fetch.set_defaults(cmd_func=mst.cmds.fetch_command)
    parser_verify.set_defaults(cmd_func=mst.cmds.verify_command)
    parser_sync.set_defaults(cmd_func=mst.cmds.sync_command)
    parser_config.set_defaults(cmd_func=mst.cmds.config_command)
    parser_keygen.set_defaults(cmd_func=mst.cmds.keygen_command)
    parser_info.set_defaults(cmd_func=mst.cmds.info_command)

    args = parser.parse_args(raw_args)
    args.verbosity = args.verbose - args.quiet
    args.parser = parser

    return args
