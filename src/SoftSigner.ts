import * as GeneratePassword from 'generate-password'
import { Signer, SignerCurve, TezosMessageUtils } from 'conseiljs';

import { CryptoUtils } from './utils/CryptoUtils'

/**
 * libsodium/ed25519
 */
export class SoftSigner implements Signer {
    readonly _secretKey: Buffer;
    private _passphrase: string;
    private _salt: Buffer;
    private _key: Buffer;
    private _lockTimout: number
    private _unlocked: boolean;

    /**
     * 
     * 
     * @param secretKey Secret key for signing.
     * @param validity Duration for keeping the key decrypted in memory.
     * @param passphrase
     */
    private constructor(secretKey: Buffer, validity: number = -1, passphrase: string = '', salt?: Buffer) {
        this._secretKey = secretKey;
        this._lockTimout = validity;
        this._passphrase = passphrase;
        this._salt = salt ? salt : Buffer.alloc(0);

        this._unlocked = validity < 0;
        this._key = Buffer.alloc(0);

        if (validity < 0) {
            this._key = secretKey;
        }
    }

    public getSignerCurve(): SignerCurve {
        return SignerCurve.ED25519
    }

    public static async createSigner(secretKey: Buffer, validity: number = 60): Promise<Signer> {
        if (validity >= 0) {
            const passphrase = GeneratePassword.generate({ length: 32, numbers: true, symbols: true, lowercase: true, uppercase: true });
            const salt = await CryptoUtils.generateSaltForPwHash();
            secretKey = await CryptoUtils.encryptMessage(secretKey, passphrase, salt);
            return new SoftSigner(secretKey, validity, passphrase, salt);
        } else {
            return new SoftSigner(secretKey);
        }
    }

    private async getKey() {
        if (!this._unlocked) {
            const k = await CryptoUtils.decryptMessage(this._secretKey, this._passphrase, this._salt);
            if (this._lockTimout == 0) {
                return k;
            }

            this._key = k;
            this._unlocked = true;
            if (this._lockTimout > 0) {
                setTimeout(() => {
                    this._key = Buffer.alloc(0);
                    this._unlocked = false;
                }, this._lockTimout * 1000);
            }
            return this._key;
        }

        return this._key;
    }

    /**
     * Signs a 
     * 
     * @param {Buffer} bytes Bytes to sign
     * @returns {Buffer} Signature
     */
    public async signOperation(bytes: Buffer): Promise<Buffer> {
        return CryptoUtils.signDetached(TezosMessageUtils.simpleHash(bytes, 32), await this.getKey());
    }

    /**
     * Convenience function that uses Tezos nomenclature to sign arbitrary text.
     * 
     * @param message UTF-8 text
     * @returns {Promise<string>} base58check-encoded signature prefixed with 'edsig'
     */
    public async signText(message: string): Promise<string> {
        const messageSig = await CryptoUtils.signDetached(Buffer.from(message, 'utf8'), await this.getKey());

        return TezosMessageUtils.readSignatureWithHint(messageSig, 'edsig');
    }

    /**
     * * Convenience function that uses Tezos nomenclature to sign arbitrary text. This method produces a 32-byte blake2s hash prior to signing.
     * 
     * @param message UTF-8 text
     * @returns {Promise<string>} base58check-encoded signature prefixed with 'edsig'
     */
    public async signTextHash(message: string): Promise<string> {
        const messageHash = TezosMessageUtils.simpleHash(Buffer.from(message, 'utf8'), 32);
        const messageSig = await CryptoUtils.signDetached(messageHash, await this.getKey());

        return TezosMessageUtils.readSignatureWithHint(messageSig, 'edsig');
    }
}
