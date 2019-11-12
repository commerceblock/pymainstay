# Mainstay Client

A command-line tool used to manage interaction with the Mainstay.xyz 
service. The tool can be used to perform state attestations, retrieve and collate 
slot-proofs and to verify proofs of immutable sequence via connection to a Bitcoin 
full node or explorer. 

## Requirements

* Python3

To trustlessly verify proofs, an RPC connection to a `bitcoind` node must be provided. 

## Installation

Via PyPi:

    $ pip3 install py-mainstay

or directly from source:

    $ python3 setup.py install

## Usage

