import * as createHMAC from 'create-hmac';
import * as createHash from 'create-hash';

import * as secp256k1 from 'tiny-secp256k1';
// need to figure out how to use libsodium for ed25519
// import * as ed25519 from '';

export interface CurveInfo {
    bip32Name: string;
    isValidPrivateKey: (key: Buffer) => boolean;
}

export const SECP256K1: CurveInfo = {
    bip32Name: 'Bitcoin seed', 
    isValidPrivateKey: function(key: Buffer): boolean {
        return secp256k1.isPrivate(key);
    }
}

export const ED25519: CurveInfo = {
    bip32Name: 'ed25519 seed',
    isValidPrivateKey: function(key: Buffer): boolean {
        return true;
    }
}

// taken from https://github.com/bitcoinjs/bip32/blob/master/ts-src/crypto.ts
export function hash160(buffer: Buffer): Buffer {
    const sha256Hash: Buffer = createHash('sha256')
        .update(buffer)
        .digest();
    try {
        return createHash('rmd160')
            .update(sha256Hash)
            .digest();
    } catch (err) {
        return createHash('ripemd160')
            .update(sha256Hash)
            .digest();
    }
}

export function hmacSHA512(key: Buffer, data: Buffer): Buffer {
    return createHMAC('sha512', key)
        .update(data)
        .digest();
}