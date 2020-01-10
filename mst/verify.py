# Copyright (c) 2019 CommerceBlock Team
# Use of this source code is governed by an MIT
# license that can be found in the LICENSE file.

import sys
import json
import argparse
import binascii
import io
import logging
import appdirs
import os
import time
import urllib.request
import requests
import threading
import math
import hmac
import hashlib
from datetime import datetime
from queue import Queue, Empty
from typing import Sequence

from binascii import hexlify

import mst
import mst.ecc as ecc
import mst.rpchost as rpc
from mst.ecc import bfh, hfu,  bh2u, to_bytes, sha256, Hash, hash_160

BASE_PUBKEYS = ["03639a65bfb3dd5a579e65231a4e70327aba358e956d6e10f7ea2e25dd631e4d66","024f714a1b93697c5a3865259ac3a865bb306e8b720c3bec46bae3298ef3fa7964","035ea174407b61b85fc83993084c471f78095779737a75adf2a2e52cdd2a36edd3"]
MAINSTAY_CHAINCODES = ["8c57ec95db9ddab3b17ea5ae8c1411bbc0859d1a5262ff67d475cc880e14cfd9","087c28f8989d4a5e692127dbaeffc86b7d2d44b878b3a585b2c98967c854ed8d","2f94eeb596c3c7d9a5746b17150412a3c5f4f9f999ffb2395fc59a14bcfc4271"]

APPDIRS = appdirs.AppDirs('msc','mainstay')

hash_encode = lambda x: bh2u(x[::-1])
hash_decode = lambda x: bfh(x)[::-1]

def rev_hex(s):
    return bh2u(bfh(s)[::-1])

def int_to_hex(i: int, length: int=1) -> str:
    """Converts int to little-endian hex string.
    `length` is the number of bytes available
    """
    if not isinstance(i, int):
        raise TypeError('{} instead of int'.format(i))
    range_size = pow(256, length)
    if i < -range_size/2 or i >= range_size:
        raise OverflowError('cannot convert int {} to hex ({} bytes)'.format(i, length))
    if i < 0:
        # two's complement
        i = range_size + i
    s = hex(i)[2:].rstrip('L')
    s = "0"*(2*length - len(s)) + s
    return rev_hex(s)

def hmac_oneshot(key: bytes, msg: bytes, digest) -> bytes:
    if hasattr(hmac, 'digest'):
        # requires python 3.7+; faster
        return hmac.digest(key, msg, digest)
    else:
        return hmac.new(key, msg, digest).digest()

def multisig_script(public_keys: Sequence[str], m: int) -> str:
    n = len(public_keys)
    assert n <= 15
    assert m <= n
    op_m = '52'
    op_n = '53'
    keylist = ['21' + k for k in public_keys]
    return op_m + ''.join(keylist) + op_n + 'ae'

def CKD_pub(cK, c, n):
    if n < 0:
        logging.error('ERROR: bip32 index is negative')
        sys.exit(1)
    return _CKD_pub(cK, c, bfh(rev_hex(int_to_hex(n,4))))

def _CKD_pub(cK, c, s):
    I = hmac_oneshot(c, cK + s, hashlib.sha512)
    pubkey = ecc.ECPrivkey(I[0:32]) + ecc.ECPubkey(cK)
    if pubkey.is_at_infinity():
        logging.error("ECC ERROR: Invlaid public key")
        sys.exit(1)
    cK_n = pubkey.get_public_key_bytes(compressed=True)
    c_n = I[32:]
    return cK_n, c_n

def hash_merkle_root(merkle_branch: Sequence[str], tx_hash: str, slot: int):
    try:
        h = hash_decode(tx_hash)
        merkle_branch_bytes = [hash_decode(item) for item in merkle_branch]
        int(slot)  # raise if invalid
    except:
        logging.error('ERROR: Merke proof decode failed')
        sys.exit(1)        

    for i, item in enumerate(merkle_branch_bytes):
        h = Hash(item + h) if ((slot >> i) & 1) else Hash(h + item)
    return hash_encode(h)

def get_path_from_commitment(com):
    path_size = 16
    child_size = 2
    if len(com) != path_size*child_size:
        logging.error('ERROR: commitment incorrect size for path')
        sys.exit(1) 
    derivation_path = []
    for it in range(path_size):
        index = com[it*child_size:it*child_size+child_size]
        derivation_path.append(index)
    return derivation_path

def tweak_script(path):
    tweaked_keys = []
    for ikey in range(len(BASE_PUBKEYS)):
        cK = bytes.fromhex(BASE_PUBKEYS[ikey])
        c = bytes.fromhex(MAINSTAY_CHAINCODES[ikey])
        for index in path:
            cK, c = CKD_pub(cK, c, int.from_bytes(index,'big'))
        tweaked_keys.append(bh2u(cK))
    tweaked_script = multisig_script(tweaked_keys, 2)
    return hash_160(bytes.fromhex(tweaked_script))

def verify_p2c_commitment(proof, tx):
    #verify the pay-to-contract proof merkle root in the Bitcoin transaction
    try:
        script_addr = tx["vout"][0]["scriptPubKey"]["hex"]
    except:
        try:
            script_addr = tx["outputs"][0]["script"]
        except:
            logging.error("Bitcoin API error")
            logging.error(str(tx))
            sys.exit(1)            
    try:
        nout = len(tx["vout"])
    except:
        nout = len(tx["outputs"])
    if nout != 1:
        logging.error('ERROR: staychain TxID '+sproof["txid"]+' has more than one output')
        logging.error('Staychain verification failed.')
        sys.exit(1)
    try:
        commitment = proof['merkle_root']
    except:
        logging.error('ERROR: slot proof malformation')
        sys.exit(1)
    commitment_path = get_path_from_commitment(bytes.fromhex(rev_hex(commitment)))
    tweaked_addr = 'a914' + tweak_script(commitment_path).hex() + '87'
    if script_addr == tweaked_addr:
        return True
    else:
        logging.error('ERROR: staychain TxID '+proof["txid"]+' commitment verification failure')
        sys.exit(1)

def verify_slot_proof(slot, proof):
    #verify the Merkle path of the slot proof
    try:
        merkle_root = proof['merkle_root']
        commitment = proof['commitment']
        ops = proof['ops']
    except:
        logging.error('ERROR: slot proof malformation')
        sys.exit(1)
    calculated_proof_root = hash_merkle_root([pth['commitment'] for pth in ops], commitment, slot)
    if calculated_proof_root == merkle_root:
        return True
    else:
        logging.error('ERROR: commitment '+commitment+' slot-proof verification failure')
        sys.exit(1)

def verify_commitment(slot,sproof,bitcoin_node):
    #verify single commitment against the bitcoin blockchain
    pv = verify_slot_proof(slot,sproof)
    vins = []
    if not pv:
        logging.error('ERROR: Slot-proof verification failed')
        sys.exit(1)
    if '@' in bitcoin_node:
        #connect via RPC
        connection = rpc.RPCHost(bitcoin_node)
        try:
            tx = connection.call('getrawtransaction',sproof["txid"],True)
        except Exception as e:
            logging.error('ERROR: getrawtransaction RPC error')
            logging.error(str(e))
            sys.exit(1)
        tv = verify_p2c_commitment(sproof,tx)
        for txin in tx["vin"]:
            vins.append(txin["txid"])
        if not tv:
            logging.error('ERROR: P2C verification failed. Merkle root: '+sproof["merkle_root"])
            logging.error('TxID: '+sproof['txid'])
            sys.exit(1)
        try:
            block = connection.call('getblock',tx["blockhash"])
        except Exception as e:
            logging.error('ERROR: getblock RPC error')
            logging.error(str(e))
            sys.exit(1)
        try:
            ver = (sproof["commitment"],sproof["txid"],tx["blockhash"],str(block["height"]),datetime.fromtimestamp(block["time"].strftime('%c')))
        except:
            logging.error('TxID '+sproof["txid"]+' unconfirmed')
            sys.exit(1)
        return ver, vins
    else:
        #attempt to use http API
        try:
            req = requests.get(bitcoin_node+sproof["txid"])
            tx = req.json()
        except:
            logging.error('ERROR: get Bitcoin transaction via HTTP API failure')
            sys.exit(1)
        tv = verify_p2c_commitment(sproof,tx)
        for txin in tx["inputs"]:
            vins.append(txin["prev_hash"])
        if not tv:
            logging.error('ERROR: P2C verification failed. Merkle root: '+sproof["merkle_root"])
            sys.exit(1)
        try:
            ver = (sproof["commitment"],sproof["txid"],tx["block_hash"],str(tx["block_height"]),tx["confirmed"])
        except:
            logging.error('TxID '+sproof["txid"]+' unconfirmed')
            sys.exit(1)
        return ver, vins
