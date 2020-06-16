import { Signer, TezosMessageUtils } from 'conseiljs';

import { CryptoUtils } from './utils/CryptoUtils'

/**
 *  libsodium/ed25519
 */
export class SoftSigner implements Signer {
    readonly secretKey: Buffer;

    constructor(secretKey: Buffer) {
        this.secretKey = secretKey;
    }

    /**
     * Signs a 
     * 
     * @param {Buffer} bytes Bytes to sign
     * @param {Buffer} secretKey Secret key
     * @returns {Buffer} Signature
     */
    public async signOperation(bytes: Buffer): Promise<Buffer> {
        return CryptoUtils.signDetached(TezosMessageUtils.simpleHash(bytes, 32), this.secretKey);
    }

    /**
     * Convenience function that uses Tezos nomenclature to sign arbitrary text.
     * 
     * @param keyStore Key pair to use for signing
     * @param message UTF-8 test
     * @returns {Promise<string>} base58check-encoded signature prefixed with 'edsig'
     */
    public async signText(message: string): Promise<string> {
        const messageSig = await CryptoUtils.signDetached(Buffer.from(message, 'utf8'), this.secretKey);

        return TezosMessageUtils.readSignatureWithHint(messageSig, 'edsig');
    }
}
