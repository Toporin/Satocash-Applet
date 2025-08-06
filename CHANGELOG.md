# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Satocash applet full versions follows this format: vX.Y-Z.W where:
* X.Y refers to the PROTOCOL VERSION: changes that impact compatibility with the client side (e.g new functionalities, major patch...)
* Z.W refers to changes with no impact on compatibility of the client (e.g minor patches, optimizations...)

## [0.2-0.1] (beta)

P2PK locked token support for the Satocash card. 
The process is mostly backward compatible with previous Satocash version, and only requires an additional 4 bytes of storage per proof. 
It's still a bit experimental, but the big picture is the following:

* the client application gets a P2PK pubkey and derivation path from the card using satocash-get-bip32-extendedkey. 
A unique key is derived for each call using BIP32 derivation (the seed is generated randomly by the card).

* The client get P2PK proof from the mint locked with the given pubkey, then import the proof into the card with satocash-import-proof. 
The client must provide the nonce as 'secret' and derivation path in addition to the usual info (keyset, unblinded-key, amount). 
Note that the P2PK secret (JSON as string) is deserialized at this step (more on this later).

* To get the proof back, first the proof data is exported using satocash-export-proofs. 
This returns the nonce as 16-byte 'secret' and 'unblinded-key' data as usual. 
To recover the signature for P2PK proofs, client must additionaly call satocash-export-p2pk-sig.

* There are additional checks to ensure that only one P2PK proof can be imported as 'unspent' for each unique P2PK key: if you import multiple proofs 
locked with the same pubkey, only the fist imported proof will be marked as 'unspent' (this is to avoid offline double-spending).

There is an important caveat: for efficient storage and compatibility, the P2PK secret is not stored as a serialized string, 
but only the "nonce" and "data" (actually the derivation path) is stored in Satocash. 
The Secret string is then reconstructed by the client (POS) from the raw data after export. 
This implies to deserialize/reserialize the proof.secret JSON. 
However, this serialization is not canonical, which will be an issue if different clients (sender & receiver) serialize the secret JSON object in different ways, 
since the P2PK signature will not be valid for mismatched serialized strings. 
To avoid this issue, it would help if the NUT11 specification requires a canonical serialization for the proof.secret JSON (see [this issue](https://github.com/cashubtc/nuts/issues/278)).


## [0.1-0.1]

Initial version