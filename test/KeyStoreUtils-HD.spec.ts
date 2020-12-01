import chai, { expect } from 'chai';
import chaiAsPromised from 'chai-as-promised';

import * as bip39 from 'bip39';
import { TezosMessageUtils } from 'conseiljs';

import { CryptoUtils } from '../src/utils/CryptoUtils';
const wrapper = require('../src/utils/WrapperWrapper');
import { KeyStoreUtils } from '../src/KeyStoreUtils';

chai.use(chaiAsPromised);

// From Trezor Connect's test suite: https://github.com/trezor/connect/blob/31d4bb595bed72ef666f0d5c8aacb85f0e55588a/tests/__fixtures__/tezosGetAddress.js
// seed generated using bip39.js
const trezorTZ1TestVector = {
    "mnemonic": "alcohol woman abuse must during monitor noble actual mixed trade anger aisle",
    "derivations": [
        {
            "path": "m/44'/1729'/0'",
            "publicKey": "edpkuxZ5W8c2jmcaGuCFZxRDSWxS7hp98zcwj2YpUZkJWs5F7UMuF6",
            "publicKeyHash": "tz1ckrgqGGGBt4jGDmwFhtXc1LNpZJUnA9F2"
        },
        {
            "path": "m/44'/1729'/1'",
            "publicKey": "edpkuVKVFyqTnp4axajmxTnCcSHN7v1kRhVpBC25GEZQVT2ZzSpdJY",
            "publicKeyHash": "tz1cTfmc5uuBr2DmHDgkXTAoEcufvXLwq5TP"
        }
    ]

}

// Test vector generated from Ledger Nano X (Secure Element v1.2.4-1, Microcontroller v2.8)
const ledgerTestVector = {
    "mnemonic": "offer input range bread tortoise antenna model before secret dish tongue perfect able badge phrase any swim special eager kangaroo skill winner kiss million",
    "passphrase": "",
    "derivations": [
        {
            "path": "m/44'/1729'",
            "publicKey": '00191807d59ab6c8587665f899ff6499a8e3bdd89bf04687f4768a101296448358',
            "publicKeyHash": 'tz1gzULUaujk7hmgePtaQLh1FYMXLybumEvz'
        },
        {
            "path": "m/44'/1729'/0'",
            "publicKey": '000f042115e93de0c1a81c4eaeeb6df14eba498a5d35da345ddc6fe9da7141d59c',
            "publicKeyHash": 'tz1edpEAejAuhWsQVGNNQExmjnFvvMLdoR7r'
        },
        {
            "path": "m/44'/1729'/0'/0'",
            "publicKey": '0017341727bf0497d50b59a88f334bd000c224dcb41ed8c034de7b174681e2c3b6',
            "publicKeyHash": 'tz1cJ3c6ZxdUDdvKPGYh8HiGr4ZTFg9fvk8D'
        },
        {
            "path": "m/44'/1729'/0'/0'/0'",
            "publicKey": '008551e497c56ce28331172442284c395e218e95e5c00cc243478b7a1119327bf6',
            "publicKeyHash": 'tz1Suh9rCywdGKfijMc2UdxSHvRvoAczmW2z'
        },
        {
            "path": "m/44'/1729'/2147483647'",
            "publicKey": '0063062127bd0b27dbfba16f053701e794cc9e8888d40f90f3e042ce28a7f07bf3',
            "publicKeyHash": 'tz1SfrAC7bXSpo4LTvngDXcuJHBV3hCFb4bT'
        },
        {
            "path": "m/44'/1729'/2147483647'/1'",
            "publicKey": '0087676f2bf5224d9feea3825a565c16521e982626094631a8dcabe8416f50a3a6',
            "publicKeyHash": 'tz1cTBDJrfYU9t8X7PRagws5o3jT33HsjFBF'
        },
        {
            "path": "m/44'/1729'/2147483647'/1'/2147483646'",
            "publicKey": '0001ce46928a4f8555fdcac9f202483077cc926db02cdf05d57555d68eb74a2ada',
            "publicKeyHash": 'tz1iWtQqrN87VYz9tiQPHu5pDXw4ovM8RJCS'
        }
    ]
}

describe('Trezor tz1 address test vector', () => {
    it('Trezor tz1 address test vector', async () => {
        for (const sample of trezorTZ1TestVector.derivations) {
            const keystore = await KeyStoreUtils.restoreIdentityFromMnemonic(trezorTZ1TestVector.mnemonic, '', '', sample.path);

            expect(keystore.publicKey).to.equal(sample.publicKey);
            expect(keystore.publicKeyHash).to.equal(sample.publicKeyHash);
        }
    });
});

describe('Ledger Tezos paths test vector', () => {
    it('Ledger Tezos paths test vector', async () => {
        for (const sample of ledgerTestVector.derivations) {
            const keystore = await KeyStoreUtils.restoreIdentityFromMnemonic(ledgerTestVector.mnemonic, '', '', sample.path);

            expect(TezosMessageUtils.writePublicKey(keystore.publicKey)).to.equal(sample.publicKey);
            expect(keystore.publicKeyHash).to.equal(sample.publicKeyHash);
        }
    });
});

describe('Failure tests', () => {
    it('Invalid derivation path failures', async () => {
        // TODO
    });
});
