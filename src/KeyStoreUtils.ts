import * as bip39 from 'bip39';
import * as secp256k1 from 'secp256k1';
import * as Ed25519 from 'ed25519-hd-key';

import { KeyStore, KeyStoreCurve, KeyStoreType, SignerCurve } from 'conseiljs';
import { TezosMessageUtils } from 'conseiljs';

import { CryptoUtils } from './utils/CryptoUtils'

/**
 * A set of helper functions for managing the Fundraiser and software-generated keys.
 */
export namespace KeyStoreUtils {
    /**
     * 
     * @param strength Number of words to include in the mnemonic, defaults to 256 (24 words).
     */
    export function generateMnemonic(strength: number = 256) {
        return bip39.generateMnemonic(strength);
    }

    /**
     * 
     * @param strength 
     * @param password 
     * @param mnemonic 
     */
    export async function generateIdentity(strength: number = 256, password: string = '', mnemonic?: string): Promise<KeyStore> {
        return restoreIdentityFromMnemonic((mnemonic || bip39.generateMnemonic(strength)), password);
    }

    /**
     * 
     * 
     * @param {string} secretKey Secret key to restore public key and hash from.
     */
    export async function restoreIdentityFromSecretKey(secretKey: string): Promise<KeyStore> {
        const secretKeyBytes = TezosMessageUtils.writeKeyWithHint(secretKey, 'edsk');
        const keys = await recoverKeys(secretKeyBytes);

        const publicKey = TezosMessageUtils.readKeyWithHint(keys.publicKey, 'edpk');
        const publicKeyHash = TezosMessageUtils.computeKeyHash(keys.publicKey, 'tz1');

        return { publicKey, secretKey, publicKeyHash, curve: KeyStoreCurve.ED25519, storeType: KeyStoreType.Mnemonic };
    }

    /**
     * Produced a keypair from the provided seed and optional password using the ED25519 curve.
     * 
     * @param {string} mnemonic Space-separated BIP39 words, required.
     * @param {string} password Optional password, if none provided, defaults to empty string
     * @param {string} pkh Optional public key hash (tz1 address)
     * @param {string} derivationPath Optional derivation path
     * @param {boolean} validate Mnemonic validation flag, defaults to true
     */
    export async function restoreIdentityFromMnemonic(mnemonic: string, password: string = '', pkh?: string, derivationPath?: string, validate: boolean = true): Promise<KeyStore> {
        if (validate) {
            if (![12, 15, 18, 21, 24].includes(mnemonic.split(' ').length)) { throw new Error('Invalid mnemonic length.'); }
            if (!bip39.validateMnemonic(mnemonic)) { throw new Error('The given mnemonic could not be validated.'); }
        }

        let keys: { secretKey: Buffer, publicKey: Buffer };
        const seed = await bip39.mnemonicToSeed(mnemonic, password);
        if (derivationPath !== undefined && derivationPath.length > 0) {
            const keySource = Ed25519.derivePath(derivationPath, seed.toString("hex"));
            const combinedKey = Buffer.concat([keySource.key, keySource.chainCode]);

            keys = await recoverKeys(combinedKey);
        } else {
            keys = await generateKeys(seed.slice(0, 32));
        }

        const secretKey = TezosMessageUtils.readKeyWithHint(keys.secretKey, 'edsk');
        const publicKey = TezosMessageUtils.readKeyWithHint(keys.publicKey, 'edpk');
        const publicKeyHash = TezosMessageUtils.computeKeyHash(keys.publicKey, 'tz1');

        if (!!pkh && publicKeyHash !== pkh) { throw new Error('The given mnemonic and passphrase do not correspond to the supplied public key hash'); }

        return {publicKey, secretKey, publicKeyHash, curve: KeyStoreCurve.ED25519, storeType: KeyStoreType.Mnemonic, seed: mnemonic, derivationPath};
    }

    /**
     * Unlocks an identity supplied during the 2017 Tezos fundraiser.
     * 
     * To get a Tezos test nets account go to https://faucet.tzalpha.net
     * 
     * @param {string} mnemonic Fifteen-word mnemonic phrase from fundraiser PDF.
     * @param {string} email Email address from fundraiser PDF.
     * @param {string} password Password from fundraiser PDF.
     * @param {string} pkh The public key hash supposedly produced by the given mnemonic and passphrase
     * @returns {Promise<KeyStore>} Wallet file
     */
    export async function restoreIdentityFromFundraiser(mnemonic: string, email: string, password: string, pkh: string): Promise<KeyStore> {
        return await restoreIdentityFromMnemonic(mnemonic, email + password, pkh);
    }

    /**
     * 
     * @param seed 
     */
    export async function generateKeys(seed: Buffer): Promise<{ publicKey: Buffer, secretKey: Buffer}> {
        const keys = await CryptoUtils.generateKeys(seed);
        return { publicKey: keys.publicKey, secretKey: keys.secretKey };
    }

    export async function recoverKeys(secretKey: Buffer): Promise<{ publicKey: Buffer, secretKey: Buffer}> {
        const keys = await CryptoUtils.recoverPublicKey(secretKey);
        return { publicKey: keys.publicKey, secretKey: keys.secretKey };
    }

    /**
     * 
     * @param message 
     * @param passphrase 
     * @param salt 
     */
    export async function decryptMessage(message: Buffer, passphrase: string, salt: Buffer): Promise<Buffer> {
        return CryptoUtils.decryptMessage(message, passphrase, salt);
    }

    /**
     * 
     * @param message 
     * @param passphrase 
     * @param salt 
     */
    export async function encryptMessage(message: Buffer, passphrase: string, salt: Buffer): Promise<Buffer> {
        return CryptoUtils.encryptMessage(message, passphrase, salt);
    }

    /**
     * Convenience function that uses Tezos nomenclature to check signature of arbitrary text. This method supports the ed25519 curve.
     * 
     * @param signature Message signature, prefixed with `edsig`.
     * @param message Plain text of the message in UTF-8 encoding.
     * @param publicKey Public key to verify the signature against, prefixed with `edpk`.
     * @param prehash If true, a 32-byte blake2s message hash is used for verification instead of the plain message. Default is false.
     * * @returns {Promise<boolean>}
     */
    export async function checkTextSignature(signature: string, message: string, publicKey: string, prehash = false): Promise<boolean> {
        let messageBytes: Buffer;
        if (prehash) {
            messageBytes = TezosMessageUtils.simpleHash(Buffer.from(message, 'utf8'), 32);
        } else {
            messageBytes = Buffer.from(message, 'utf8');
        }

        return checkSignature(signature, messageBytes, publicKey);
    }

    /**
     * Compare a given signature against a message and public key.
     * 
     * @param signature Message signature to verify in Tezos string format, prefixed with edsig, or spsig for ED25519 and SECP256K1 signatures.
     * @param bytes Message to check the signature against
     * @param publicKey Public key to check the signature against
     * @param prehash
     */
    export async function checkSignature(signature: string, bytes: Buffer, publicKey: string, prehash = false): Promise<boolean> {
        const sigPrefix = signature.slice(0, 5);
        const keyPrefix = publicKey.slice(0, 4);
        let curve = SignerCurve.ED25519;

        if (sigPrefix === 'edsig' && keyPrefix === 'edpk') {
            curve = SignerCurve.ED25519;
        } else if (sigPrefix === 'spsig' && keyPrefix === 'sppk') {
            curve = SignerCurve.SECP256K1;
        } else if (sigPrefix === 'p2sig' && keyPrefix === 'p2pk') {
            throw new Error('secp256r1 curve is not currently supported');
        } else {
            throw new Error(`Signature/key prefix mismatch ${sigPrefix}/${keyPrefix}`);
        }

        let messageBytes: Buffer;
        if (prehash) {
            messageBytes = TezosMessageUtils.simpleHash(bytes, 32);
        } else {
            messageBytes = bytes
        }

        const sig = TezosMessageUtils.writeSignatureWithHint(signature, sigPrefix);
        const pk = TezosMessageUtils.writeKeyWithHint(publicKey, keyPrefix);

        if (curve === SignerCurve.ED25519) {
            return await CryptoUtils.checkSignature(sig, bytes, pk);
        }

        if (curve === SignerCurve.SECP256K1) {
            return secp256k1.ecdsaVerify(sig, bytes, pk);
        }

        return false;
    }
}
