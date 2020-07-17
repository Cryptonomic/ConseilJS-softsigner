import createHmac from 'create-hmac';

import { BIP32Name, CurveInfo } from './types'

const wrapper = require('./WrapperWrapper');

/**
 * Tezos cryptography helpers for the ed25519 curve.
 */
export namespace CryptoUtils {
    /**
     * Generates a salt for key derivation.
     * 
     * @returns {Promise<Buffer>} Salt
     */
    export async function generateSaltForPwHash() : Promise<Buffer> {
        const s = await wrapper.salt();
        return s;
    }

    /**
     * Encrypts a given message using a passphrase
     * 
     * @param {string} message Message to encrypt
     * @param {string} passphrase User-supplied passphrase
     * @param {Buffer} salt Salt for key derivation
     * @returns {Buffer} Concatenated bytes of nonce and cipher text
     */
    export async function encryptMessage(message: Buffer, passphrase: string, salt: Buffer) : Promise<Buffer> {
        const keyBytes = await wrapper.pwhash(passphrase, salt)
        const n = await wrapper.nonce();
        const nonce = Buffer.from(n);
        const s = await wrapper.close(message, nonce, keyBytes);
        const cipherText = Buffer.from(s);

        return Buffer.concat([nonce, cipherText]);
    }

    /**
     * Decrypts a given message using a passphrase
     * 
     * @param {Buffer} message Concatenated bytes of nonce and cipher text
     * @param {string} passphrase User-supplied passphrase
     * @param {Buffer} salt Salt for key derivation
     * @returns {string} Decrypted message
     */
    export async function decryptMessage(message: Buffer, passphrase: string, salt: Buffer) : Promise<Buffer> {
        const keyBytes = await wrapper.pwhash(passphrase, salt)
        const m = await wrapper.open(message, keyBytes);
        return Buffer.from(m);
    }

    /**
     * Generate key pair from seed.
     * 
     * @param seed 
     */
    export async function generateKeys(seed: Buffer) {
        const k = await wrapper.keys(seed);

        return { privateKey: k.privateKey, publicKey: k.publicKey };
    }

    /**
     * Generate key pair from secret key by recovering the seed.
     * 
     * @param secretKey 
     */
    export async function recoverPublicKey(secretKey: Buffer) {
        const k = await wrapper.publickey(secretKey);

        return { privateKey: k.privateKey, publicKey: k.publicKey };
    }

    /**
     * Sign arbitrary bytes with a secret key.
     * 
     * @param payload 
     * @param secretKey 
     */
    export async function signDetached(payload: Buffer, secretKey: Buffer): Promise<Buffer> {
        const b = await wrapper.sign(payload, secretKey)
        return Buffer.from(b);
    }

    export async function checkSignature(signature: Buffer, payload: Buffer, publicKey: Buffer): Promise<boolean> {
        return await wrapper.checkSignature(signature, payload, publicKey);
    }

    export const ed25519: CurveInfo = {
        bip32Name: BIP32Name.ED25519,
        async publicKey(secretKey: Buffer): Promise<Buffer> {
            const pk = Buffer.from((await wrapper.seed_keypair(secretKey)).publicKey.buffer, 'hex');
            return pk;
        }
    }

    export async function hmacSHA512(message:Buffer, key: Buffer): Promise<Buffer> {
        return createHmac('sha512', key).update(message).digest();
    }
}
