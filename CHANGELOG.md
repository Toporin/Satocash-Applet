# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

Satocash applet full versions follows this format: vX.Y-Z.W where:
* X.Y refers to the PROTOCOL VERSION: changes that impact compatibility with the client side (e.g new functionalities, major patch...)
* Z.W refers to changes with no impact on compatibility of the client (e.g minor patches, optimizations...)

## Unreleased

## [0.1-0.3]

Add amount limits for PIN-less payments when exporting proofs with satocashExportProofs(). 
An amount threshold can be defined for each supported unit (currently SAT, msat, USD, EUR). By default, amount threshold is zero (PIN mandatory for any payment).
A new threshold amount can be defined using command APDU setPinlessAmount(). For unsupported unit, PIN is always required if PIN is enabled in PIN policy.
If PIN is validated, cumulative amount is for the concerned unit is reset to zero, otherwise cumulative amount is increased with the total amount represented by the proofs, 
and if this cumulative amount is higher than the allowed threshold, an exception is thrown.
PIN for payment can also be disabled completely through the correct PIN policy using setPinPolicy().

## [0.1-0.2]

By default, the authentikey (a secp256k1 private key used to authenticate the card) is generated randomly on card and is therefore unique.
This version supports importing an authentikey during personalization (before card setup) using the import_PKI_ndef_authentikey() command APDU. 
This key can then be shared by multiple devices for improved privacy.

New instruction: INS_IMPORT_PKI_NDEF_AUTHENTIKEY = (byte) 0x9B;

## [0.1-0.1]

Initial version