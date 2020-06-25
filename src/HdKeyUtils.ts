import { CryptoUtils } from './utils/CryptoUtils'
import { BIP32Name, CurveInfo, HDNode } from './utils/types'

/**
 * Implementation of [SLIP10](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) for ed25519 curve that is used by Tezos to generate tz1 addresses.
 */
export namespace HDKeyUtils {
    const HARDENED = 0x80000000;

    /**
     * 
     * @param node 
     * @param index 
     */
    export async function derive(node: HDNode, index: number): Promise<HDNode> {
        // only support curve ed25519 - hardened derivation required
        if (node.curve.bip32Name === BIP32Name.ED25519 && !(index & HARDENED)) { throw new Error('ED25519 derivation requires hardened paths'); }

        // data = 0x00 || ser256(kpar) || ser32(index)
        const data = Buffer.allocUnsafe(1 + 32 + 4);
        data[0] = 0x00; // 1 bit
        node.privateKey.copy(data, 1); // 32 bits
        data.writeUInt32BE(index, 33); // 4 bits

        // create privateKey and chainCode
        const i = CryptoUtils.hmacSHA512(node.chainCode, data);
        const iL = i.slice(0, 32);
        const iR = i.slice(32);

        return {
            privateKey: iL, 
            chainCode: iR, 
            publicKey: undefined,
            curve: node.curve,
            index: index,
            depth: node.depth + 1
        };
    }

    /**
     * 
     * @param node 
     * @param path 
     */
    export async function derivePath(node: HDNode, path: string): Promise<HDNode> {
        if (!BIP32Path(path)) { throw new Error('Invalid derivation path'); }

        const splitPath = path.split('/').slice(1);
        let nodeResult = node;
        for (const indexStr of splitPath) { 
            let index;
            if (indexStr.slice(-1) === `'`) {
                index = parseInt(indexStr.slice(0, -1), 10);
                nodeResult = await derive(nodeResult, index + HARDENED);
            } else {
                throw new Error('ED25519 derivation requires hardened paths');
            };
        }

        return nodeResult;
    }

    /**
     * 
     * @param seed 
     * @param curve 
     */
    export async function fromSeed(seed: Buffer, curve: CurveInfo): Promise<HDNode> {
        // need to verify seed length is 512 bits
        let i = CryptoUtils.hmacSHA512(Buffer.from(curve.bip32Name, 'utf8'), seed);
        const iL = i.slice(0, 32);
        const iR = i.slice(32);
        return {
            privateKey: iL, 
            chainCode: iR, 
            publicKey: undefined,
            curve: curve,
            index: undefined, // undefined for master node
            depth: 0
        };
    }

    /**
     * Validates the incoming value as a BIP32 derivation path
     */
    function BIP32Path(value: string): boolean {
        return (value.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null);
    }
}
