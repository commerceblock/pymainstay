# Copyright (C) 2016-2018 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Client.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Client, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

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
import base64
from queue import Queue, Empty

from binascii import hexlify

import mst
import mst.rpchost as rpc
from mst.verify import verify_commitment
from mst.ecc import key_gen, ECPrivkey


APPDIRS = appdirs.AppDirs('msc','mainstay')

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def get_settings(args):
    filename = APPDIRS.user_data_dir + '/config.json'
    try:
        with open(filename,'r') as file:
            config = json.load(file)
        logging.info("Reading parameters from config file")
    except:
        logging.info("No configuration file found")
        config = {}
    return config

def save_settings(settings):
    if not os.path.exists(APPDIRS.user_data_dir):
        os.makedirs(APPDIRS.user_data_dir)
    filename = APPDIRS.user_data_dir + '/config.json'
    try:
        with open(filename, 'w') as f:
            json.dump(settings,f)
    except:
        logging.error("Write config error")

def load_proofseq(slot):
    filename = APPDIRS.user_data_dir + "/slot_" + str(slot) + "_sequence.msp"
    try:
        with open(filename, 'r') as f:
            seq = json.loads(f.read())
    except:
        seq = []
    return seq

def save_proofseq(slot,seq):
    if not os.path.exists(APPDIRS.user_data_dir):
        os.makedirs(APPDIRS.user_data_dir)
    filename = APPDIRS.user_data_dir + "/slot_" + str(slot) + "_sequence.msp"
    try:
        with open(filename, 'w') as f:
            json.dump(seq,f)
    except:
        logging.error("Write proof sequence error")

def get_proof_from_commit(slot,commit):
    filename = APPDIRS.user_data_dir + "/slot_" + str(slot) + "_sequence.msp"
    try:
        with open(filename, 'r') as f:
            seq = json.loads(f.read())
    except:
        return None
    for addproof in seq:
        if addproof["commitment"] == commit:
            return addproof
    logging.info("Commitment not in saved sequence proof")
    return None

def add_to_proofseq(seq,sproof):
    addproof = {"txid":sproof["response"]["attestation"]["txid"],
                "commitment":sproof["response"]["merkleproof"]["commitment"],
                "merkle_root":sproof["response"]["merkleproof"]["merkle_root"],
                "ops":sproof["response"]["merkleproof"]["ops"],
                "date":sproof["response"]["attestation"]["inserted_at"],
                "height":'0'}
    seq.insert(0,addproof)
    return seq

def writetofile(output,filename):
    filename = os.getcwd() + '/' + filename
    try:
        with open(filename,'w') as file:
            json.dump(output,file)
    except:
        logging.error("write output to file error")

def readfromfile(filename):
    filename = os.getcwd() + '/' + filename
    try:
        with open(filename) as file:
            seq = json.load(file)
        return seq
    except:
        logging.error("Error reading from file")
        sys.exit(1)        

def get_mainstay_api(url,rstring):
    try:
        r = requests.request('GET', url+rstring, timeout=2)
        r.raise_for_status()
        proof = r.json()
        return proof
    except:
        logging.error("get mainstay proof http error")
        return False
    return True

def update_proofseq(service_url,seq,slot,txid):
    # add all recent slot proofs to the proof sequence
    try:
        top_txid = seq[0]["txid"]
    except:
        top_txid = " "
    rstring = "/api/v1/position?position="+str(slot)
    pp = get_mainstay_api(service_url,rstring)
    try:
        np = math.ceil(pp["pages"])
    except:
        logging.error("get position proofs http error")
        return False        
    ip = 0
    for page in range(np):
        if page > 0:
            try:
                rstring = "/api/v1/position?position="+str(slot)+"&page="+str(page+1)
                pp = get_mainstay_api(service_url,rstring)
            except:
                logging.error("get position proofs page http error")
                return False
        for com in pp["data"]:
            try:
                rstring = "/api/v1/commitment/commitment?commitment="+com["commitment"]
                sproof = get_mainstay_api(service_url,rstring)
                if sproof["response"]["attestation"]["txid"] != top_txid:
                    addproof = {"txid":sproof["response"]["attestation"]["txid"],
                                "commitment":sproof["response"]["merkleproof"]["commitment"],
                                "merkle_root":sproof["response"]["merkleproof"]["merkle_root"],
                                "ops":sproof["response"]["merkleproof"]["ops"],
                                "date":sproof["response"]["attestation"]["inserted_at"],
                                "height":'0'}
                    seq.insert(ip,addproof)
                    ip = ip + 1
                else:
                    return seq
            except:
                logging.error("get commit proof error")
                return False             
            if sproof["response"]["attestation"]["txid"] == txid:
                return seq
    return seq

def attest_command(args):

    print(os.getcwd())
    print(args.slot)
    print(args.filename)
    print(APPDIRS.user_data_dir)

def fetch_command(args):

    settings = get_settings(args)

    if args.slot:
        slot = args.slot
    else:
        try:
            slot = settings["slot"]
        except:
            logging.error("Missing slot ID in config and argument")
            sys.exit(1)

    if args.txid:
        txid = args.txid
    else:
        try:
            slot = settings["txid"]
        except:
            txid = None

    # proof type
    if args.commitment:
        if args.commitment == 0:
            rstring = "/api/v1/commitment/latestproof?position="+str(slot)
            sproof = get_mainstay_api(args.service_url,rstring)
            if args.filename and sproof:
                writetofile(sproof,args.filename)
            if args.output and sproof:
                print(sproof)
            return True
        if len(args.commitment) != 64:
            logging.error("Invlaid commitment string: incorrect length")
            sys.exit(1)
        if not is_hex(args.commitment):
            logging.error("Invlaid commitment string: not hex")
            sys.exit(1)
        rstring = "/api/v1/commitment/commitment?commitment="+args.commitment
        sproof = get_mainstay_api(args.service_url,rstring)
        if args.filename and sproof:
            writetofile(sproof,args.filename)
        if args.output and sproof:
            print(sproof)     
        return True

    if args.list:
        commitment_list = [item for item in args.list.split(',')]
        for commitment in commitment_list:
            if len(args.commitment) != 64:
                logging.error("Invlaid commitment string: incorrect length")
                sys.exit(1)
            if not is_hex(args.commitment):
                logging.error("Invlaid commitment string: not hex")
                sys.exit(1)
        seq = []
        for commitment in commitment_list:
            rstring = "/api/v1/commitment/commitment?commitment="+args.commitment
            sproof = get_mainstay_api(args.service_url,rstring)
            seq = add_to_proofseq(seq,sproof)
        if args.filename and sproof:
            writetofile(seq,args.filename)
        if args.output and sproof:
            print(seq)

    if args.txid:
        if args.txid == '0':
            txid = None
        elif len(args.txid) != 64:
            logging.error("Invlaid TxID string: incorrect length")
            sys.exit(1)
        elif not is_hex(args.txid):
            logging.error("Invlaid TxID string: not hex")
            sys.exit(1)
        else:
            txid = args.txid

        seq = load_proofseq(slot)
        seq = update_proofseq(args.service_url,seq,slot,txid)

        if args.filename and seq:
            writetofile(seq,args.filename)
        if args.output and seq:
            print(seq)
        save_proofseq(slot,seq)
        return True

    if args.update:
        txid = None
        seq = load_proofseq(slot)
        olen = len(seq)
        if olen < 1:
            logging.error("No proof sequence to update. Run -i first.")
            sys.exit(1)
        seq = update_proofseq(args.service_url,seq,slot,txid)
        save_proofseq(slot,seq)
        if args.filename and seq:
            writetofile(seq[0:-olen],args.filename)
        if args.output and seq:
            print(seq[0:-olen])

def verify_command(args):

    settings = get_settings(args)

    if args.bitcoin_node:
        bitcoin_node = args.bitcoin_node
    else:
        try:
            slot = settings["bitcoin_node"]
        except:
            logging.error("Missing bitcoin node connection details in config and argument")
            sys.exit(1)

    if args.slot:
        slot = args.slot
    else:
        try:
            slot = settings["slot"]
        except:
            logging.error("Missing slot ID in config and argument")
            sys.exit(1)

    if args.txid:
        txid_base = args.txid
    else:
        try:
            txid_base = settings["slot"]
        except:
            txid_base = None

    if args.commitment:
        if len(args.commitment) != 64:
            logging.error("Invlaid commitment string: incorrect length")
            sys.exit(1)
        if not is_hex(args.commitment):
            logging.error("Invlaid commitment string: not hex")
            sys.exit(1)
        addproof = get_proof_from_commit(slot,args.commitment)
        if not addproof:
            logging.info("Retrieving slof proof from "+args.service_url)
            rstring = "/api/v1/commitment/commitment?commitment="+args.commitment
            sproof = get_mainstay_api(args.service_url,rstring)
            addproof = {"txid":sproof["response"]["attestation"]["txid"],
                        "commitment":sproof["response"]["merkleproof"]["commitment"],
                        "merkle_root":sproof["response"]["merkleproof"]["merkle_root"],
                        "ops":sproof["response"]["merkleproof"]["ops"],
                        "date":sproof["response"]["attestation"]["inserted_at"]}
        ver,_ = verify_commitment(slot,addproof,bitcoin_node)
        ver_com = "Verified commitment "+ver[0]+" in slot "+str(slot)+" in TxID "+ver[1]
        ver_block = "In Bitcoin block "+ver[2]+" height "+ver[3]+" at "+ver[4]
        print(ver_com+"\n"+ver_block)
        return True

    if args.filename:
        seq = readfromfile(args.filename)
    elif args.proof:
        if args.proof == '0':
            seq = load_proofseq(slot)
        else:
            try:
                seq = json.loads(args.proof)
            except:
                logging.error("Invlaid JSON for proof sequence")
                sys.exit(1)
    else:
        logging.error("No proof sequence to verify: use option -p or -f to specify proof")
        sys.exit(1)
    if len(seq) < 1:
        logging.error("No proof sequence to verify")
        sys.exit(1)

    verout = []
    nseq = []
    txin = None
    stxid = None
    schain = []
    #verify proof sequence against bitcoin staychain
    for sproof in seq:
        if txin:
            if sproof["txid"] not in txin:
                logging.error("TxID "+sproof["txid"]+ "not input to "+stxid)
                sys.exit(1)
        ver,txin = verify_commitment(slot,sproof,bitcoin_node)
        stxid = sproof["txid"]
        verout.append(ver)
        logging.debug("Verified commitment "+ver[0]+" in slot "+str(slot)+" in TxID "+ver[1])
        logging.debug("In Bitcoin block "+ver[2]+" height "+ver[3]+" at "+ver[4])
        sproof["height"] = ver[3]
        nseq.append(sproof)
        schain.append(sproof["txid"])

    if args.proof:
        if args.proof == '0':
            save_proofseq(slot,nseq)

    # verify staychain txid
    if txid_base:
        if txid_base in schain:
            print("Verified proof sequence against staychain "+txid_base+" slot "+str(slot)+"\n")
        else:
            logging.error("Proof sequence not on specified staychain")
            sys.exit(1)
    else:
        print("Verified proof sequence\n")

    print("End commitment in block "+verout[0][2]+" height "+verout[0][3]+" at "+verout[0][4])
    print("Start commitment in block "+verout[-1][2]+" height "+verout[-1][3]+" at "+verout[-1][4])

    if args.list:
        commitment_list = [item for item in args.list.split(',')]
        for commitment in commitment_list:
            if len(args.commitment) != 64:
                logging.error("Invlaid commitment string: incorrect length")
                sys.exit(1)
            if not is_hex(args.commitment):
                logging.error("Invlaid commitment string: not hex")
                sys.exit(1)
        if len(commitment_list) != len(nseq):
            logging.error("Commitment list is of different length to proof sequence")
            sys.exit(1)
        for itr in rangle(len(nseq)):
            if commitment_list[itr] != nseq[itr]["commitment"]:
                logging.error("Commitment list sequence missmatch at position "+str(itr))
                sys.exit(1)
        print("Verified proof sequence against commitment list")

def sync_command(args):

    settings = get_settings(args)

    if args.bitcoin_node:
        bitcoin_node = args.bitcoin_node
    else:
        try:
            slot = settings["bitcoin_node"]
        except:
            logging.error("Missing bitcoin node connection details in config and argument")
            sys.exit(1)

    if args.sidechain_node:
        sidechain_node = args.sidechain_node
    else:
        try:
            slot = settings["sidechain_node"]
        except:
            logging.error("Missing sidechain node connection details in config and argument")
            sys.exit(1)

    if args.slot:
        slot = args.slot
    else:
        try:
            slot = settings["slot"]
        except:
            logging.error("Missing slot ID in config and argument")
            sys.exit(1)

    #get the staychain base txid from the sidechain genesis block
    if bitcoin_node[0:6] != 'http://':
        bitcoin_node = 'http://' + bitcoin_node
    connection = rpc.RPCHost(bitcoin_node)
    try:
        gbh = connection.call('getblockhash',0)
        gb = connection.call('getblock',gbh)
    except:
        logging.error('ERROR: sidechain getblock RPC failure')
        sys.exit(1)
    txid_base = gb["attestationhash"]   

    if args.slot:
        slot = args.slot
    else:
        try:
            slot = settings.get["slot"]
        except:
            slot = int(gb['mappinghash'],16)
            if slot > 999999:
                logging.error('ERROR: invalid slot position in sidechain header')
                sys.exit(1)

    seq = load_proofseq(slot)
    seq = update_proofseq(args.service_url,seq,slot,txid)

    verout = []
    nseq = []
    txin = None
    stxid = None
    schain = []
    #verify proof sequence against bitcoin staychain
    for sproof in seq:
        if txin:
            if sproof["txid"] not in txin:
                logging.error("TxID "+sproof["txid"]+ "not input to "+stxid)
                sys.exit(1)
        ver,txin = verify_commitment(slot,sproof,bitcoin_node)
        stxid = sproof["txid"]
        verout.append(ver)
        logging.debug("Verified commitment "+ver[0]+" in slot "+str(slot)+" in TxID "+ver[1])
        logging.debug("In Bitcoin block "+ver[2]+" height "+ver[3]+" at "+ver[4])
        sproof["height"] = ver[3]
        nseq.append(sproof)
        schain.append(sproof["txid"])

    if args.proof:
        if args.proof == '0':
            save_proofseq(slot,nseq)

    # verify staychain txid
    if txid_base:
        if txid_base in schain:
            print("Verified proof sequence against staychain "+txid_base+" slot "+str(slot))
            print("Staychain base "+txid_base+" committed to sidechain genesis")
        else:
            logging.error("Proof sequence not on committed staychain")
            sys.exit(1)
    else:
        print("Verified proof sequence\n")

    #verify commitment sequence against sidechain
    prevh = 0
    sblocks = []
    for sproof in nseq:
        if commitment == '0'*64: continue
        try:
            block = connection.call('getblock',sproof["commitment"])
        except:
            logging.error("Verification failure: "+sproof["commitment"]+" not a sidechain block hash")
            sys.exit(1)
        if prevh != 0:
            if prevh < block["height"]:
                logging.error("Verification failure: block "+sproof["commitment"]+" out of sequence")
                sys.exit(1)
        prevh = block["height"]
        sblocks.append(prevh)

    print("Verified sidechain attestation sequence")
    print("Latest attestated sidechain block: "+nseq[0]["commitment"]+" height "+str(sblocks[0]))

    if args.filename and nseq:
        writetofile(nseq,args.filename)
    save_proofseq(slot,nseq)  

def config_command(args):

    settings = get_settings(args)

    if args.slot:
        settings["slot"] = args.slot

    if args.txid:
        settings["txid"] = args.txid

    if args.bitcoin_node:
        settings["bitcoin_node"] = args.bitcoin_node

    if args.sidechain_node:
        settings["txid"] = args.sidechain_node

    if args.api_token:
        settings["api_token"] = args.api_token

    if args.privkey:
        settings["privkey"] = args.privkey

    save_settings(settings)

def keygen_command(args):

    settings = get_settings(args)

    print(settings)

    if args.gen:
        entropy = args.gen
        privkey = key_gen(entropy)
        settings["privkey"] = privkey
        print("Generated key: "+str(privkey))
        save_settings(settings)
        return True  

    if args.public:
        if args.public == '0':
            try:
                privkey = settings["privkey"]
            except:
                logging.error("Privkey not present in config file")
                sys.exit(1)
        else:
            if len(args.public) != 64:
                logging.error("Invlaid private key: incorrect length")
                sys.exit(1)
            if not is_hex(args.public):
                logging.error("Invlaid private key: not hex")
                sys.exit(1)
            privkey = args.public   
        public_key = ECPrivkey(bytes.fromhex(privkey)).get_public_key_hex(compressed=True)
        print("Public key: "+str(public_key))

    if args.sign:
        try:
            privkey = settings["privkey"]
        except:
            logging.error("Privkey not present in config file")
            sys.exit(1)
        key = ECPrivkey(bytes.fromhex(privkey))
        if len(args.sign) != 64:
            logging.error("Invlaid commitment: incorrect length")
            sys.exit(1)
        if not is_hex(args.sign):
            logging.error("Invlaid commitment: not hex")
            sys.exit(1)
        message = bytes.fromhex(args.sign)
        sig = key.sign_message(message, True)
        print("Signature: "+str(base64.b64encode(sig).decode('ascii')))

    
