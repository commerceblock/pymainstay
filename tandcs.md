# T&Cs Immutability with Mainstay

This document describes a system and interface for enabling users to trustlessly prove and verify the publication and provenance of a document that describes terms and conditions (i.e. a contract) for a specified service. 

## Background

Before any service is provided to a member of the public, the user must agree to the contract between the user and the provider - these terms and conditions (T&Cs) of the service provision typicaly define the rights and responsibilities of both parties. These T&Cs are typically presented to the user at the point of purchase/engagement to which they must agree in order to continue. The problem with this model however is how to handle the scenario when there is a dispute between the user and provider over the precise T&Cs the user agreed to. This type of dispute can be prevented via a mechanism or arangement to record the exact wording of a specific T&Cs by a trusted third party, however the trusted third party (i.e. a notorisation service) could be influenced by or collaborate with provider, or be hacked. Trusted third parties also typically involve significant costs related to oversight and auditing requirements, and must be recognised and trusted by all parties and/or the courts. 

To remove the requirement for a trusted notary to authenticate the wording of a specific T&Cs issued at a particular point in time, there are several techniques involving cryptograpic authentication that are currently used:

1. Digital signatures: The T&Cs are encoded into a specified format, which is then digitally signed with a private key that belongs to the provider. The corresponding public key is published by the provider and tied to it (via a certificate authority), which can be used to prove the provider signed the specific wording of the T&Cs. In the case of a dispute the user can prove that the provider authorised specific T&Cs. 

2. Digital timestamping: The T&Cs are encoded into the specified format and a cryptographic hash is generated (which uniquely identifies the T&Cs). This cryptographic hash is then included in a transaction in a public blockchain (i.e. Bitcoin). In this case the user can prove that specific T&Cs *existed* at the time they were committed to the blockchain (without trust in any third party). 

A combination of these techniqies enables a user to prove that specific T&Cs were both approved by the provider AND existed (at least) at a known date/time, without trust. 

This does not however conclusively resolve any dispute between the user and the provider over the specific T&Cs agreed to. The timestamp prevents the provider from retrospectively changing previously published T&Cs (i.e. a proof of existance) however the provider could timestamp several different sets of T&Cs with different conditions. T&Cs are updated all the time: the provider could claim that a different set of T&Cs applied at the time the user signed up - they could provide a timestamp of these substituted T&Cs claiming they applied at the time the user signed up, but in actual fact a different set of T&Cs were presented to the user, which were simultaneously timestamped. The existance of one timestamp does not preclude the existance of another, conflicting timestamp at the same time. 

Mainstay provides a solution to this by producing a trustless *proof of publication* on the globally unique Bitcoin blockchain. This enables the provider to commit to only *one* specific set of T&Cs at any one time, and to enable the user to verify and prove that only one specific set of T&Cs has been committed globaly. The user can verify and prove that the T&Cs are unique to the published Mainstay *slot* of the provider and that they were the only ones that applied at the time of signup. The provider can of course update the T&Cs, but they must replace the commitment in the Mainstay slot to prove the update is globally unique, which can be independently verified by the user. 

## Protocol

The protocol for achieving this is straightforward within the Mainstay framework. The provider signs up to the Mainstay service and is allocated a slot ID and base staychain transaction ID which constitutes the globally unique identifier (`slot_id:txid`). The unique identifier (`slot_id:txid`) can then be published and associated publicly with the provider (i.e. on the provider website, or in a PKI certificate). The provider has full control over any documents committed to the slot. To process of commitment would then operate as follows:

1. Provider finalises T&Cs and chooses the format (e.g. plain text, html, pdf). 
2. The provider then commits the document to the allocated slot (via the `msc` client or cloud app). 
3. The provider then adds the unique identifier (`slot_id:txid`) to a code widget which can be added to the webpage/webdocument displaying the T&Cs. 

The user can then review the T&Cs and click on the Mainstay widget icon which will perform a verification via the Mainstay API and Bitcoin blockchain and display the details to the user. This will include verification that the hash of the T&Cs is committed to the globally unique slot, that this commitment is unique to the slot (latest) and the block information (time/date). The user is then given the option to download the slot-proof and T&Cs (as a file) which can be stored and used as an independent proof (along with the immutable blockchain) in the case of a dispute. 
