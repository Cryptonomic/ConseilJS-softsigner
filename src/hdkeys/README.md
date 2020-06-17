# HD Keys on Tezos

This is an evolving summary of the current knowledge accumulated on implementing an heirarchal deterministic derivation for Tezos keys.

## BIP32

The obvious place to start is [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), the canonical standard for this type of key derivation from Bticoin-land. This uses the SECP256k1 curve, and allows for both hardened and non-hardened keys. Non-hardened keys allow for child *public* keys to be derived from a parent *public* key alone, and their canonical use case is accepting payments to a server that would derive many public keys without holding any private keys. However, we are only interested in hardened keys as they are not only more secure (details on this in BIP32), but more importantly the heirarchal derivation for the ed25519 curve (tz1* addresses) does not work with non-hardened keys.

The standard describes the derivation of a master key from a seed, and child derivations for private -> private, public -> public, and private -> public. However, for hardened keys, only the private -> private is valid. Obviously, once you derive the child private key you can generate the public key, though. 

[Typescript/Javascript implementation](https://github.com/bitcoinjs/bip32) from BitcoinJS.

### BIP32 and ed25519

Due to the [bit clamping](https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/) used in most Curve25519 implementations, BIP32 schemes using this curve are vulnerable to "small subgroup attacks". There is an explanation from some Web 3 Foundation researchers here: [[1]](https://forum.web3.foundation/t/key-recovery-attack-on-bip32-ed25519/44) [[2]](https://github.com/w3f/hd-ed25519/), as well as more discussion on the moderncrypto mailing list here: [[3]](https://moderncrypto.org/mail-archive/curves/2017/000858.html) [[4]](https://moderncrypto.org/mail-archive/curves/2017/000866.html), and finally, a summary of the situation a Solana developer: [[5]](https://github.com/solana-labs/solana/issues/6301#issuecomment-551184457).

## SLIP10

Trezor's [SLIP10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) seems to be the most coherent solution proposed, as well as the only one with a deployed implementation to refer to. It is an adaptation of BIP32 that also supports the ed25519 and NIST P-256 curves. The differences are in the message used to initialize the HMAC in the master key derivation, as well as the retry loop in the child derivation function (BIP32 increments the index, while SLIP10 increments the padding). 

As Trezor is open source, this also has a [reference implementation](https://github.com/trezor/trezor-firmware/blob/master/crypto/bip32.c). Many test vectors are also provided in the spec.

## Ledger's implementation

[This](https://github.com/LedgerHQ/nanos-secure-sdk/blob/1f2706941b68d897622f75407a868b60eb2be8d7/include/os.h#L1163) is the function declaration for BIP32 derivation, from Ledger's SDK. And here is a [Reddit thread](https://www.reddit.com/r/ledgerwallet/comments/71tphi/is_there_a_javascript_implementation_of_os_perso/) where Ledger's cofounder claims it's following Trezor's SLIP10.  

## BIP44 and SLIP44

[BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) standardizes the semantics of the first 5 levels of indices for derivation: 
```
    m / purpose' / coin_type' / account' / change / address_index
```  
And [SLIP44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) offers an extended list of registered coin types. For Tezos, we use:
```
    m / 44' / 1729' / account' / change'
```
Where the account and change fields are simply indexed from 0.