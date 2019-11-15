# Mainstay Client

A command-line tool used to manage interaction with the **mainstay.xyz** immutability
service. The tool can be used to perform state attestations, retrieve and collate 
proofs and to verify proofs of immutable sequence via connection to a Bitcoin 
full node or Bitcoin block-explorer API. 

## Requirements

* Python3

To trustlessly verify proofs, an RPC connection to a `bitcoind` node must be provided. 

## Installation

Via PyPi:

    $ pip3 install py-mainstay

or directly from source:

    $ python3 setup.py install

## Usage

The Mainstay client interface (`msc`) can be used to fetch and verify proof sequences, syncronize and verify the immutability of Mainstay sidechains, perform authenticated data commitments and attestations, and generate and manage *mainstay.xyz* authentication keys. The interface is used via commands to perform different operations with specified arguments. The commands available can be listed with the `--help` argument:

	$ msc -h

```
	usage: msc [-h] [-q] [-v]
	           {attest,a,fetch,f,verify,v,sync,s,config,c,keygen,k} ...

	Mainstay client

	optional arguments:
	  -h, --help            show this help message and exit
	  -q, --quiet           Be more quiet.
	  -v, --verbose         Be more verbose. Both -v and -q may be used multiple
	                        times.

	Commands:
	  Mainstay operations are performed via commands:

	  {attest,a,fetch,f,verify,v,sync,s,config,c,keygen,k}
	    attest (a)          Commit data to a Mainstay slot
	    fetch (f)           Fetch proofs from the Mainstay service
	    verify (v)          Verify Mainstay proofs against the Bitcoin blockchain
	    sync (s)            Syncronise sidechain to Bitcoin via a sequence proof
	    config (c)          Set configuration
	    keygen (k)          Generate signing keys for attestations
```

For each command, the possible arguments can be again listed with the `--help` flag. E.g. 

	$ msc attest -h

```
usage: msc attest [-h] [-f FILENAME | -c COMMITMENT] [-s SLOT]
                  [--url SERVICE_URL] [-t API_TOKEN] [-k PRIVKEY]

	optional arguments:
	  -h, --help            show this help message and exit
	  -f FILENAME, --file FILENAME
	                        Attest the SHA256 hash of the specified file.
	  -c COMMITMENT, --commit COMMITMENT
	                        Hex string of the 32 bytes commitment.
	  -s SLOT, --slot SLOT  Specify the slot position index
	  --url SERVICE_URL     URL for the Mainstay connector service. Default:
	                        https://mainstay.xyz
	  -t API_TOKEN, --token API_TOKEN
	                        API token for the specified slot position.
	  -k PRIVKEY, --privkey PRIVKEY
	                        Private key for signing the commitment.
```

### Configuration

The client can be used in a stateless fashon, with all configuration supplied via the command-line options, however a configutation file (`config.json`) can be used, which is located in the application data directory. The current configuration, and the location of the application data directory, can be retrieved as follows:

	$ msc config -g

All configuration is set via the same command. For connection to a particular slot, the slot position (`-s`), the API token (`-t`) and the authentication key (`-k`) can be set initially, so they do not have to be specified for each subsequent call. 

### Attestation

To perform commitments to a specified *mainstay.xyz* slot requires an API token that will have been provided on initialisation of the slot. In addition, if a public key was specified on initialisation, the commitment must be signed by the corresponding private key. The signature is computed by the client if the private key is provided (or is in the config). 

The client will send 32 byte commitment supplied as an argument (`-c`) to the specified slot, or the SHA256 hash of a specified file path (`-f`). For example:

	$ msc attest -c 4db3dbb10b33d94389446982f022ee55be8eaefa7d8f40046054a693f23a1c85

The client will return whether the commitment has been recieved by the *mainstay.xyz* successfully. 

### Proof retrieval

The client can retrive, store and update sequence proofs for a specified or configured slot position. This requires no token or authentication, as the proofs are publicly accessible. All retrieved sequence proofs are stored locally in the application data directory (the location of directory can be found with the `config -g` command), and can also optionally be saved to a specified file or printed to standard output. 


