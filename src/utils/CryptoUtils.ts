import * as createHMAC from 'create-hmac';
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


    export enum BIP32Name {
        SECP256K1 = "Bitcoin seed",
        ED25519 = "ed25519 seed",
        NISTP256 = "Nist256p1 seed"
    }

    export interface CurveInfo {
        curveName: string,
        bip32Name: BIP32Name;
        publicKey(privateKey: Buffer): Promise<Buffer>;
    }

    export const ed25519: CurveInfo = {
        curveName: 'ed25519',
        bip32Name: BIP32Name.ED25519,
        async publicKey(privateKey: Buffer): Promise<Buffer> {
            return await wrapper.publickey(privateKey);
        }
    }

    export function hmacSHA512(key: Buffer, data: Buffer): Buffer {
        return createHMAC('sha512', key)
            .update(data)
            .digest();
    }
}
