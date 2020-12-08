import { Signer, SignerCurve, TezosMessageUtils } from 'conseiljs';

import { CryptoUtils } from './utils/CryptoUtils'

/**
 * Softsigner is a wrapper for libsodium. It leverages the ED25519 curve to perform cryptographic operations relevant for the Tezos blockchain.
 */
export class SoftSigner implements Signer {
    readonly _secretKey: Buffer;
    private _isEncrypted: boolean;
    private _salt: Buffer;

    /**
     * 
     * 
     * @param secretKey Secret key for signing.
     * @param validity Duration for keeping the key decrypted in memory.
     * @param passphrase
     */
    private constructor(secretKey: Buffer, isEncrypted: boolean = false, salt?: Buffer) {
        this._secretKey = secretKey;
        this._isEncrypted = isEncrypted;
        this._salt = salt ? salt : Buffer.alloc(0);
    }

    public getSignerCurve(): SignerCurve {
        return SignerCurve.ED25519
    }

    public static async createSigner(secretKey: Buffer, password: string = ''): Promise<Signer> {
        if (password.length > 0) {
            const salt = await CryptoUtils.generateSaltForPwHash();
            const encryptedKey = await CryptoUtils.encryptMessage(secretKey, password, salt);
            return new SoftSigner(encryptedKey, true, salt);
        }

        return new SoftSigner(secretKey);
    }

    private async getKey(password: string = '') {
        if (this._isEncrypted && password.length > 0) {
            return await CryptoUtils.decryptMessage(this._secretKey, password, this._salt);
        }

        return this._secretKey;
    }

    /**
     * This method in intended to sign Tezos operations. It produces a 32-byte blake2s hash prior to signing the buffer.
     * 
     * @param {Buffer} bytes Bytes to sign
     * @returns {Buffer} Signature
     */
    public async signOperation(bytes: Buffer, password: string = ''): Promise<Buffer> {
        return CryptoUtils.signDetached(TezosMessageUtils.simpleHash(bytes, 32), await this.getKey(password));
    }

    /**
     * Convenience function that uses Tezos nomenclature to sign arbitrary text.
     * 
     * @param message UTF-8 text
     * @returns {Promise<string>} base58check-encoded signature prefixed with 'edsig'
     */
    public async signText(message: string, password: string = ''): Promise<string> {
        const messageSig = await CryptoUtils.signDetached(Buffer.from(message, 'utf8'), await this.getKey(password));

        return TezosMessageUtils.readSignatureWithHint(messageSig, 'edsig');
    }

    /**
     * * Convenience function that uses Tezos nomenclature to sign arbitrary text. This method produces a 32-byte blake2s hash prior to signing.
     * 
     * @param message UTF-8 text
     * @returns {Promise<string>} base58check-encoded signature prefixed with 'edsig'
     */
    public async signTextHash(message: string, password: string = ''): Promise<string> {
        const messageSig = await this.signOperation(Buffer.from(message, 'utf8'), password);

        return TezosMessageUtils.readSignatureWithHint(messageSig, 'edsig');
    }
}
