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
import requests
import threading
import hashlib
import math
import base64
import git
from binascii import hexlify
import mst
import mst.rpchost as rpc
from mst.verify import verify_commitment
from mst.ecc import key_gen, ECPrivkey, Hash


APPDIRS = appdirs.AppDirs('msc','mainstay')

def sha256sum(filename):
    h  = hashlib.sha256()
    b  = bytearray(128*1024)
    mv = memoryview(b)
    with open(filename, 'rb', buffering=0) as f:
        for n in iter(lambda : f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()

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
            json.dump(settings,f, indent=2, sort_keys=True)
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
            json.dump(seq,f, indent=2, sort_keys=True)
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
        logging.error("Get mainstay proof http error")
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
    total = pp["total"]
    try:
        np = math.ceil(pp["pages"])
    except:
        logging.error("ERROR: get position proofs http error")
        return False        
    ip = 0
    fbase = False
    for page in range(np):
        logging.debug("Reading page "+str(page+1)+" of "+str(np))
        if page > 0:
            try:
                rstring = "/api/v1/position?position="+str(slot)+"&page="+str(page+1)
                pp = get_mainstay_api(service_url,rstring)
            except:
                logging.error("ERROR: get position proofs page http error")
                sys.exit(1) 
        for sproof in pp["data"]:
            try:
                logging.debug("TxID: "+sproof["txid"])
                if sproof["txid"] != top_txid:
                    addproof = {"txid":sproof["txid"],
                                "commitment":sproof["commitment"],
                                "merkle_root":sproof["merkle_root"],
                                "ops":sproof["ops"],
                                "date":sproof["date"],
                                "height":'0'}
                    if sproof["confirmed"]:
                        seq.insert(ip,addproof)
                        ip = ip + 1
                else:
                    fbase = True
                    break
            except:
                logging.error("ERROR: get commit proof error")
                sys.exit(1)
            if sproof["txid"] == txid:
                fbase = True
                break
        if fbase: break

    # check total
    rstring = "/api/v1/position?position="+str(slot)
    pp = get_mainstay_api(service_url,rstring)
    if total == pp["total"]:
        return seq
    else:
        logging.error("ERROR: pages updated during retrieval - please re-run fetch.")
        sys.exit(1)     

def attest_command(args):

    settings = get_settings(args)

    if args.slot:
        slot = str(args.slot)
    else:
        try:
            slot = str(settings["slot"])
        except:
            logging.error("Missing slot ID in config and argument")
            return False

    if args.api_token:
        token = args.api_token
    else:
        try:
            token = settings["api_token"]
        except:
            logging.error("Missing API token in config and argument")
            return False

    if args.privkey:
        privkey = args.privkey
    else:
        try:
            privkey = settings["privkey"]
        except:
            privkey = None
            logging.info("No private key: unsigned commitment")

    if args.commitment:
        if len(args.commitment) != 64:
            logging.error("Invlaid commitment string: incorrect length")
            return False
        if not is_hex(args.commitment):
            logging.error("Invlaid commitment string: not hex")
            return False
        commitment = args.commitment

    if args.filename:
        if args.filename[0] == '/':
            filename = args.filename
        else:
            filename = os.getcwd() + '/' + args.filename
        try:
            commitment = sha256sum(filename)
        except:
            logging.error("ERROR: could not open specified file")
            return False
        logging.info("SHA256("+args.filename+"): "+commitment)

    if args.git:
        if args.git == '0':
            try:
                git_path = str(settings["git_path"])
            except:
                logging.error("Missing Git repo path in config and argument")
                return False
        else:
            git_path = args.git
        try:
            repo = git.Repo(git_path)
            line = repo.git.log('--pretty=oneline','-1')
        except:
            logging.error("Invalid Git repository")
            return False
        padding = '0'*24
        commitment = line[0:40] + padding
        logging.info('HEAD: '+line[0:40])

    if args.directory:
        if args.directory == '0':
            try:
                dir_path = str(settings["directory"])
            except:
                logging.error("Missing directory path in config and argument")
                return False
        else:
            dir_path = args.directory
        try:
            filelist = os.listdir(dir_path)
        except:
            logging.error("ERROR: Invalid directory path.")
            return False

        filelist.sort()

        if dir_path[-1] != '/':
            dir_path += '/'
        time = 0
        cstream = ''
        nfiles = 0
        for file in filelist:
            mtime = os.path.getmtime(dir_path+file)
            if mtime <= time:
                logging.warning("WARNING: modification times out of order with name sequence")
            if os.path.isfile(dir_path+file):
                try:
                    filehash = sha256sum(dir_path+file)
                    cstream += filehash
                    time = mtime
                    nfiles += 1
                    logging.debug("File "+file)
                    logging.debug("SHA256 "+filehash)
                    logging.debug("Time "+str(time))
                except:
                    logging.error("ERROR: could not open file: "+file)
                    return False
        #create commitment from hash list
        preimage = bytes.fromhex(cstream)
        commitment = Hash(preimage).hex()
        logging.info("Hash sequence: "+str(nfiles)+" files")
        logging.info("Commitment: "+commitment)

    headers = {'Content-Type': 'application/json'}
    payload = {"commitment":commitment,"position":slot,"token":token}
    payload_enc = str(base64.b64encode(json.dumps(payload).encode('utf-8')).decode('ascii'))

    if privkey:
        key = ECPrivkey(bytes.fromhex(privkey))
        message = bytes.fromhex(commitment)
        sig = key.sign_message(message, True)
        sig_string = str(base64.b64encode(sig).decode('ascii'))
    else:
        sig_string = ""

    data = {"X-MAINSTAY-PAYLOAD":payload_enc,"X-MAINSTAY-SIGNATURE":sig_string}
    try:
        response = requests.post(args.service_url+'/api/v1/commitment/send', headers=headers, data=json.dumps(data))
        rdata = response.json()
    except:
        logging.error("ERROR: could not send request")
        return False

    if 'error' in rdata:
        logging.error("Mainstay service error: "+rdata["error"])
    else:
        logging.info("Attestation sent")

def fetch_command(args):

    settings = get_settings(args)

    if args.slot and not args.gitpath:
        slot = args.slot
    else:
        try:
            slot = settings["slot"]
        except:
            logging.error("Missing slot ID in config and argument")
            return False

    if args.txid:
        if args.txid == '0':
            try:
                txid = settings["txid"]
            except:
                txid = None
        else:
            txid = args.txid

    # proof type
    if args.commitment:
        if args.commitment == 0:
            rstring = "/api/v1/commitment/latestproof?position="+str(slot)
            sproof = get_mainstay_api(args.service_url,rstring)
            if args.filename and sproof:
                writetofile(sproof,args.filename)
            if args.output and sproof:
                logging.info(sproof)
            return True
        if len(args.commitment) != 64:
            logging.error("Invlaid commitment string: incorrect length")
            return False
        if not is_hex(args.commitment):
            logging.error("Invlaid commitment string: not hex")
            return False
        rstring = "/api/v1/commitment/commitment?commitment="+args.commitment
        sproof = get_mainstay_api(args.service_url,rstring)
        if args.filename and sproof:
            writetofile(sproof,args.filename)
        if args.output and sproof:
            logging.info(json.dumps(sproof, indent=2, sort_keys=True))
        return True

    if args.list:
        commitment_list = [item for item in args.list.split(',')]
        for commitment in commitment_list:
            if len(args.commitment) != 64:
                logging.error("Invlaid commitment string: incorrect length")
                return False
            if not is_hex(args.commitment):
                logging.error("Invlaid commitment string: not hex")
                return False
        seq = []
        for commitment in commitment_list:
            rstring = "/api/v1/commitment/commitment?commitment="+args.commitment
            sproof = get_mainstay_api(args.service_url,rstring)
            seq = add_to_proofseq(seq,sproof)
        if args.filename and sproof:
            writetofile(seq,args.filename)
        if args.output and sproof:
            logging.info(json.dumps(seq, indent=2, sort_keys=True))
        return True

    if args.gitpath:
        if args.gitpath == '0':
            try:
                git_path = str(settings["git_path"])
            except:
                logging.error("Missing Git repo path in config and argument")
                return False
        else:
            git_path = args.gitpath
        try:
            repo = git.Repo(git_path)
            gitlog = repo.git.log('--pretty=oneline')
        except:
            logging.error("Invalid Git repository")
            return False
        clist = gitlog.splitlines()
        try:
            init_txid = clist[-1][41:105]
            init_slot = clist[-1][106:]
            slotint = int(init_slot)
        except:
            logging.error("Initial Git commit not valid staychain ID")
            return False        
        if not is_hex(init_txid):
            logging.error("Invlaid Git commit staychain ID: not hex")

        seq = load_proofseq(slot)
        seq = update_proofseq(args.service_url,seq,init_slot,init_txid)

        if seq:
            if args.filename and seq:
                writetofile(seq,args.filename)
            if args.output and seq:
                logging.info(json.dumps(seq, indent=2, sort_keys=True))
            save_proofseq(slot,seq)
            logging.info("Git repo initial commit ID: "+init_txid+":"+init_slot)
            logging.info("Sequence length: "+str(len(seq)))
            logging.info("    Start: "+seq[-1]["date"])
            logging.info("    End: "+seq[0]["date"])
            return True
        else:
            logging.info("Empty sequence")
            return False

    if args.txid:
        if len(txid) != 64:
            logging.error("Invlaid TxID string: incorrect length")
            return False
        elif not is_hex(txid):
            logging.error("Invlaid TxID string: not hex")
            return False

        seq = load_proofseq(slot)
        seq = update_proofseq(args.service_url,seq,slot,txid)

        if seq:
            if args.filename and seq:
                writetofile(seq,args.filename)
            if args.output and seq:
                logging.info(json.dumps(seq, indent=2, sort_keys=True))
            save_proofseq(slot,seq)
            logging.info("Sequence length: "+str(len(seq)))
            logging.info("    Start: "+seq[-1]["date"])
            logging.info("    End: "+seq[0]["date"])
            return True
        else:
            logging.info("Empty sequence")
            return False

    if args.update:
        txid = None
        seq = load_proofseq(slot)
        if seq:
            olen = len(seq)
        else:
            olen = 0
        if olen < 1:
            logging.error("No proof sequence to update. Run -i first.")
            return False
        seq = update_proofseq(args.service_url,seq,slot,txid)

        save_proofseq(slot,seq)
        if args.filename and seq:
            writetofile(seq[0:-olen],args.filename)
        if args.output and seq:
            logging.info(json.dumps(seq[0:-olen], indent=2, sort_keys=True))
        logging.info("Added "+str(len(seq)-olen)+" proofs")
        logging.info("Sequence length: "+str(len(seq)))
        logging.info("    Start: "+seq[-1]["date"])
        logging.info("    End: "+seq[0]["date"])
        return True

    logging.info("Please specify a fetch option (fetch -h for details).")

def verify_command(args):

    settings = get_settings(args)

    if args.bitcoin_node:
        bitcoin_node = args.bitcoin_node
    else:
        try:
            slot = settings["bitcoin_node"]
        except:
            logging.error("Missing bitcoin node connection details in config and argument")
            return False

    if args.slot:
        slot = args.slot
    else:
        try:
            slot = settings["slot"]
        except:
            logging.error("Missing slot ID in config and argument")
            return False

    if args.txid:
        txid_base = args.txid
    else:
        try:
            txid_base = settings["txid"]
        except:
            txid_base = None

    if args.commitment:
        if len(args.commitment) != 64:
            logging.error("Invlaid commitment string: incorrect length")
            return False
        if not is_hex(args.commitment):
            logging.error("Invlaid commitment string: not hex")
            return False
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
        logging.info(ver_com+"\n"+ver_block)
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
                return False
    else:
        logging.error("No proof sequence to verify: use option -p or -f to specify proof")
        return False
    if len(seq) < 1:
        logging.error("No proof sequence to verify")
        return False

    if args.list:
        commitment_list = [item for item in args.list.split(',')]
        for commitment in commitment_list:
            if len(commitment) != 64:
                logging.error("Invlaid commitment string: incorrect length")
                return False
            if not is_hex(commitment):
                logging.error("Invlaid commitment string: not hex")
                return False

        itr = 0
        #loop over all slot proofs in sequence
        for sproof in seq:
            # zero commits are null and skipped
            if sproof["commitment"] == '0'*64: continue
            if commitment_list[itr] == sproof["commitment"]:
                logging.debug("Commitment "+commitment_list[itr])
                logging.debug("In TxID "+sproof["txid"])
                logging.debug("Block height "+sproof["height"])
                continue
            else:
                itr += 1
                if commitment_list[itr] == sproof["commitment"]:
                    logging.debug("Commitment "+commitment_list[itr])
                    logging.debug("In TxID "+sproof["txid"])
                    logging.debug("Block height "+sproof["height"])
                    continue
                else:
                    logging.error("Verification failed. Commitments not matched.")
                    return False
        if itr != len(commitment_list)-1:
            logging.error("Verification failed. Additional commitments on list not in proof.")
            return False  
        logging.info("Verified proof sequence against commitment list.")
        return True

    if args.gitpath:
        if args.gitpath == '0':
            try:
                git_path = str(settings["git_path"])
            except:
                logging.error("Missing Git repo path in config and argument")
                return False
        else:
            git_path = args.gitpath
        try:
            repo = git.Repo(git_path)
            gitlog = repo.git.log('--pretty=oneline')
        except:
            logging.error("Invalid Git repository")
            return False
        padding = '0'*24
        ptr = 0
        clist = gitlog.splitlines()
        matched = []
        #loop over all slot proofs in sequence
        for sproof in seq:
            # zero commits are null and skipped
            if sproof["commitment"] == '0'*64: continue
            #loop over all commits
            found = False
            for itr in range(ptr,len(clist)):
                if clist[itr][0:40]+padding == sproof["commitment"]:
                    ptr = itr
                    found = True
                    matched.append(sproof["commitment"])
                    logging.debug("Commitment "+sproof["commitment"])
                    logging.debug("In TxID "+sproof["txid"])
                    logging.debug("Block height "+sproof["height"])
                    break
            if not found:
                logging.error("Verification failed. Commitment "+sproof["commitment"][0:40]+" not in repo.")
                return False
        logging.info("Verified proof sequence against commit history to "+matched[0][0:40])
        if seq[0]["commitment"] != clist[0]:
            ncom = 0
            for commit in clist:
                if commit[0:40] == seq[0]["commitment"]: break
                ncom += 1
            logging.warning("WARNING: last "+str(ncom)+" commits not attested.")
        try:
            init_txid = clist[-1][41:105]
            init_slot = clist[-1][106:]
        except:
            logging.info("Initial Git commit not valid staychain ID")
        if init_txid in seq[-1]["txid"] and int(slot) == int(init_slot):
            logging.info("Verified Git commit history unique")
            logging.info("Base txid: "+init_txid+" slot: "+str(init_slot))
        else:
            logging.info("Staychain ID not committed to Git history")
        return True

    if args.directory:
        if args.directory == '0':
            try:
                dir_path = str(settings["directory"])
            except:
                logging.error("Missing directory path in config and argument")
                return False
        else:
            dir_path = args.directory
        try:
            filelist = os.listdir(dir_path)
        except:
            logging.error("ERROR: Invalid directory path.")
            return False

        filelist.sort()

        if dir_path[-1] != '/':
            dir_path += '/'
        time = 0
        cstream = ''
        chash = []
        flist = []
        #create list of cumulative file hashes
        for file in filelist:
            mtime = os.path.getmtime(dir_path+file)
            if mtime <= time:
                logging.warning("WARNING: modification times out of order with name sequence")
            if os.path.isfile(dir_path+file):
                try:
                    filehash = sha256sum(dir_path+file)
                    flist.insert(0,file)
                    cstream += filehash
                    time = mtime
                    preimage = bytes.fromhex(cstream)
                    commitment = Hash(preimage).hex()
                    chash.insert(0,commitment)
                except:
                    logging.error("ERROR: could not open file: "+file)
                    return False
        #loop over all slot proofs in sequence
        ptr = 0
        fmatch = []
        for sproof in seq:
            # zero commits are null and skipped
            if sproof["commitment"] == '0'*64: continue
            #loop over all commits
            found = False
            for itr in range(ptr,len(chash)):
                if chash[itr] == sproof["commitment"]:
                    ptr = itr
                    found = True
                    logging.debug("Commitment "+sproof["commitment"])
                    logging.debug("Latest file "+flist[itr])
                    logging.debug("In TxID "+sproof["txid"])
                    logging.debug("Block height "+sproof["height"])
                    fmatch.append(flist[itr])
                    break
            if not found:
                logging.error("Verification failed. Commitment "+sproof["commitment"]+" not in directory hash chain. ")
                return False
        logging.info("Verified proof sequence against directory hash chain.")
        if seq[0]["commitment"] != chash[0]:
            ncom = 0
            for commit in chash:
                if commit == seq[0]["commitment"]: break
                ncom += 1
            logging.warning("WARNING: last "+str(ncom)+" files not attested.")
            logging.warning("Last file attested: "+fmatch[0])
        return True

    verout = []
    nseq = []
    txin = None
    stxid = None
    schain = []
    #verify proof sequence against bitcoin staychain
    for sproof in seq:
        if txin:
            if sproof["txid"] not in txin:
                logging.error("Verification failed")
                logging.error("TxID "+sproof["txid"]+" not input to "+stxid)
                return False
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
        if txid_base in schain or txid_base in txin:
            logging.info("Verified proof sequence against staychain "+txid_base+" slot "+str(slot)+"\n")
        else:
            logging.error("Proof sequence verified but not on specified staychain base")
            return False
    else:
        logging.info("Verified proof sequence\n")

    logging.info("Start commitment in block "+verout[-1][2]+" height "+verout[-1][3]+" at "+verout[-1][4])
    logging.info("End commitment in block "+verout[0][2]+" height "+verout[0][3]+" at "+verout[0][4])
    return True

def sync_command(args):

    settings = get_settings(args)

    if args.bitcoin_node:
        bitcoin_node = args.bitcoin_node
    else:
        try:
            slot = settings["bitcoin_node"]
        except:
            logging.error("Missing bitcoin node connection details in config and argument")
            return False

    if args.sidechain_node:
        sidechain_node = args.sidechain_node
    else:
        try:
            slot = settings["sidechain_node"]
        except:
            logging.error("Missing sidechain node connection details in config and argument")
            return False

    if args.slot:
        slot = args.slot
    else:
        try:
            slot = settings["slot"]
        except:
            logging.error("Missing slot ID in config and argument")
            return False

    #get the staychain base txid from the sidechain genesis block
    if bitcoin_node[0:6] != 'http://':
        bitcoin_node = 'http://' + bitcoin_node
    connection = rpc.RPCHost(bitcoin_node)
    try:
        gbh = connection.call('getblockhash',0)
        gb = connection.call('getblock',gbh)
    except:
        logging.error('ERROR: sidechain getblock RPC failure')
        return False
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
                return False

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
                return False
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
            logging.info("Verified proof sequence against staychain "+txid_base+" slot "+str(slot))
            logging.info("Staychain base "+txid_base+" committed to sidechain genesis")
        else:
            logging.error("Proof sequence not on committed staychain")
            return False
    else:
        logging.info("Verified proof sequence\n")

    #verify commitment sequence against sidechain
    prevh = 0
    sblocks = []
    for sproof in nseq:
        if commitment == '0'*64: continue
        try:
            block = connection.call('getblock',sproof["commitment"])
        except:
            logging.error("Verification failure: "+sproof["commitment"]+" not a sidechain block hash")
            return False
        if prevh != 0:
            if prevh < block["height"]:
                logging.error("Verification failure: block "+sproof["commitment"]+" out of sequence")
                return False
        prevh = block["height"]
        sblocks.append(prevh)

    logging.info("Verified sidechain attestation sequence")
    logging.info("Latest attestated sidechain block: "+nseq[0]["commitment"]+" height "+str(sblocks[0]))

    if args.filename and nseq:
        writetofile(nseq,args.filename)
    save_proofseq(slot,nseq)  

def config_command(args):

    settings = get_settings(args)
    flag = False
    if args.slot:
        settings["slot"] = args.slot
        flag = True

    if args.txid:
        settings["txid"] = args.txid
        flag = True

    if args.bitcoin_node:
        settings["bitcoin_node"] = args.bitcoin_node
        flag = True

    if args.sidechain_node:
        settings["sidechain_node"] = args.sidechain_node
        flag = True

    if args.api_token:
        settings["api_token"] = args.api_token
        flag = True

    if args.privkey:
        settings["privkey"] = args.privkey
        flag = True

    if args.gitpath:
        settings["git_path"] = args.gitpath
        flag = True

    if args.directory:
        settings["directory"] = args.directory
        flag = True

    if not flag:
       logging.info(json.dumps(settings, indent=2, sort_keys=True))
       logging.info("Data directory: "+APPDIRS.user_data_dir)
       return True

    logging.info("Set new config")
    save_settings(settings)

def keygen_command(args):

    settings = get_settings(args)

    if args.gen:
        entropy = args.gen
        privkey = key_gen(entropy)
        settings["privkey"] = privkey
        logging.info("Generated key: "+str(privkey))
        save_settings(settings)
        return True  

    if args.public:
        if args.public == '0':
            try:
                privkey = settings["privkey"]
            except:
                logging.error("Privkey not present in config file")
                return False
        else:
            if len(args.public) != 64:
                logging.error("Invlaid private key: incorrect length")
                return False
            if not is_hex(args.public):
                logging.error("Invlaid private key: not hex")
                return False
            privkey = args.public   
        public_key = ECPrivkey(bytes.fromhex(privkey)).get_public_key_hex(compressed=True)
        logging.info("Public key: "+str(public_key))
        return public_key

    if args.sign:
        try:
            privkey = settings["privkey"]
        except:
            logging.error("Privkey not present in config file")
            return False
        key = ECPrivkey(bytes.fromhex(privkey))
        if len(args.sign) != 64:
            logging.error("Invlaid commitment: incorrect length")
            return False
        if not is_hex(args.sign):
            logging.error("Invlaid commitment: not hex")
            return False
        message = bytes.fromhex(args.sign)
        sig = key.sign_message(message, True)
        logging.info("Signature: "+str(base64.b64encode(sig).decode('ascii')))
        return str(base64.b64encode(sig).decode('ascii'))

    logging.info("Please specify a keygen option (keygen -h for details).")

def info_command(args):

    settings = get_settings(args)

    if args.slot:
        slot = args.slot
    else:
        try:
            slot = settings["slot"]
        except:
            logging.error("Missing slot ID in config and argument")
            return False
    try:
        rstring = "/api/v1/commitment/latestproof?position="+str(slot)
        sproof = get_mainstay_api(args.service_url,rstring)
    except:
        logging.error("ERROR: Mainstay API request error.")
    if "error" in sproof.keys():
        logging.info("Slot "+str(slot)+" not active.")
        return False

    logging.info("Slot "+str(slot)+" last commitment: "+sproof["response"]["commitment"])
    logging.info("Base ID: "+sproof["response"]["txid"]+":"+str(slot))

    if args.config:
        settings["txid"] = sproof["response"]["txid"]
        logging.info("Set new config for base TxID")
        save_settings(settings)
