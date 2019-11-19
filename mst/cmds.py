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
from mst.ecc import key_gen, ECPrivkey


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
        logging.error("ERROR: get position proofs http error")
        return False        
    ip = 0
    for page in range(np):
        if page > 0:
            try:
                rstring = "/api/v1/position?position="+str(slot)+"&page="+str(page+1)
                pp = get_mainstay_api(service_url,rstring)
            except:
                logging.error("ERROR: get position proofs page http error")
                return False
        for sproof in pp["data"]:
            try:
                if sproof["txid"] == txid and sproof["commitment"] != '0'*64:
                    return seq
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
                    return seq
            except:
                logging.error("ERROR: get commit proof error")
                return False
            if sproof["txid"] == txid:
                return seq
    return seq

def attest_command(args):

    settings = get_settings(args)

    if args.slot:
        slot = str(args.slot)
    else:
        try:
            slot = str(settings["slot"])
        except:
            logging.error("Missing slot ID in config and argument")
            sys.exit(1)

    if args.api_token:
        token = args.api_token
    else:
        try:
            token = settings["api_token"]
        except:
            logging.error("Missing API token in config and argument")
            sys.exit(1)

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
            sys.exit(1)
        if not is_hex(args.commitment):
            logging.error("Invlaid commitment string: not hex")
            sys.exit(1)
        commitment = args.commitment

    if args.filename:
        if args.filename[0] == '/':
            filename = args.file
        else:
            filename = os.getcwd() + '/' + args.filename
        try:
            commitment = sha256sum(filename)
        except:
            logging.error("ERROR: could not open specified file")
            sys.exit(1)
        print("SHA256("+args.filename+"): "+commitment)

    if args.git:
        if args.git == '0':
            try:
                git_path = str(settings["git_path"])
            except:
                logging.error("Missing Git repo path in config and argument")
                sys.exit(1)
        else:
            git_path = args.git
        try:
            repo = git.Repo(git_path)
            line = repo.git.log('--pretty=oneline','-1')
        except:
            logging.error("Invalid Git repository")
            sys.exit(1)
        padding = '0'*24
        commitment = line[0:40] + padding
        print('HEAD: '+line[0:40])

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
        logging.error("ERROR: could not open specified file")
        sys.exit(1)

    if 'error' in rdata:
        logging.error(rdata["error"])
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
            print(json.dumps(sproof, indent=2, sort_keys=True))
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
            print(json.dumps(seq, indent=2, sort_keys=True))

    if args.gitpath:
        if args.gitpath == '0':
            try:
                git_path = str(settings["git_path"])
            except:
                logging.error("Missing Git repo path in config and argument")
                sys.exit(1)
        else:
            git_path = args.gitpath
        try:
            repo = git.Repo(git_path)
            gitlog = repo.git.log('--pretty=oneline')
        except:
            logging.error("Invalid Git repository")
            sys.exit(1)
        clist = repo.splitlines()
        try:
            init_txid = clist[-1][41:105]
            init_slot = clist[-1][106:]
            slotint = int(init_slot)
        except:
            logging.error("Initial Git commit not valid staychain ID")
            sys.exit(1)        
        if not is_hex(init_txid):
            logging.error("Invlaid Git commit staychain ID: not hex")

        seq = load_proofseq(slot)
        seq = update_proofseq(args.service_url,seq,init_slot,init_txid)

        if args.filename and seq:
            writetofile(seq,args.filename)
        if args.output and seq:
            print(json.dumps(seq, indent=2, sort_keys=True))
        save_proofseq(slot,seq)
        print("Git repo initial commit ID: "+init_txid+":"+init_slot)
        print("Sequence length: "+str(len(seq)))
        print("    Start: "+seq[-1]["date"])
        print("    End: "+seq[0]["date"])
        return True

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
            print(json.dumps(seq, indent=2, sort_keys=True))
        save_proofseq(slot,seq)
        print("Sequence length: "+str(len(seq)))
        print("    Start: "+seq[-1]["date"])
        print("    End: "+seq[0]["date"])
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
            print(json.dumps(seq[0:-olen], indent=2, sort_keys=True))
        print("Added "+str(len(seq)-olen)+" proofs")
        print("Sequence length: "+str(len(seq)))
        print("    Start: "+seq[-1]["date"])
        print("    End: "+seq[0]["date"])

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
            txid_base = settings["txid"]
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
        return True

    if args.gitpath:
        if args.gitpath == '0':
            try:
                git_path = str(settings["git_path"])
            except:
                logging.error("Missing Git repo path in config and argument")
                sys.exit(1)
        else:
            git_path = args.gitpath
        try:
            repo = git.Repo(git_path)
            gitlog = repo.git.log('--pretty=oneline')
        except:
            logging.error("Invalid Git repository")
            sys.exit(1)
        padding = '0'*24
        ptr = 0
        clist = repo.splitlines()
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
                    break
            if not found:
                logging.error("Verification failed. Commitment "+sproof["commitment"]+" not in repo.")
                sys.exit(1)
        print("Verified proof sequence against commit history")

        try:
            init_txid = clist[-1][41:105]
            init_slot = clist[-1][106:]
        except:
            print("Initial Git commit not valid staychain ID")
        if init_txid in seq[-1]["txid"] and int(slot) == int(init_slot):
            print("Verified Git commit history unique")
            print("Base txid: "+init_txid+" slot: "+str(init_slot))
        else:
            print("Staychain ID not committed to Git history")
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
                logging.error("TxID "+sproof["txid"]+" not input to "+stxid)
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
        if txid_base in schain or txid_base in txin:
            print("Verified proof sequence against staychain "+txid_base+" slot "+str(slot)+"\n")
        else:
            logging.error("Proof sequence not on specified staychain")
            sys.exit(1)
    else:
        print("Verified proof sequence\n")

    print("Start commitment in block "+verout[-1][2]+" height "+verout[-1][3]+" at "+verout[-1][4])
    print("End commitment in block "+verout[0][2]+" height "+verout[0][3]+" at "+verout[0][4])

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
        settings["txid"] = args.sidechain_node
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

    if not flag:
       print(json.dumps(settings, indent=2, sort_keys=True))
       print("Data directory: "+APPDIRS.user_data_dir)
       return True

    print("Set new config")
    save_settings(settings)

def keygen_command(args):

    settings = get_settings(args)

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

def info_command(args):

    settings = get_settings(args)

    if args.slot:
        slot = args.slot
    else:
        try:
            slot = settings["slot"]
        except:
            logging.error("Missing slot ID in config and argument")
            sys.exit(1)

    rstring = "/api/v1/commitment/latestproof?position="+str(slot)
    sproof = get_mainstay_api(args.service_url,rstring)
    if "error" in sproof.keys():
        logging.error("Slot "+str(slot)+" not active")
        sys.exit(1)

    print("Slot "+str(slot)+" last commitment: "+sproof["response"]["commitment"])
    print("ID: "+sproof["response"]["txid"]+":"+str(slot))
