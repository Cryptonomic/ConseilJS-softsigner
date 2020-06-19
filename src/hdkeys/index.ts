import * as crypto from './crypto';

import * as params from './testvector-1.json';

const HARDENED = 0x80000000;

function BIP32Path(value: string): boolean {
  return value.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null;
}

// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
class HDNode {
    privateKey: Buffer;
    chainCode: Buffer;
    publicKey: Buffer | undefined;
    depth: number;

    constructor(privateKey: Buffer, chainCode: Buffer, publicKey: Buffer | undefined) {
        this.privateKey = privateKey;
        this.chainCode = chainCode;
        this.publicKey = publicKey;
    }

    isNeutered(): boolean {
        return this.privateKey === undefined;
    }

    derive(index: number): HDNode {
        // curve ed25519 - only support hardened derivation
        if (!(index & HARDENED)) 
            throw "Unhardened derivation unsupported";

        // data = 0x00 || ser256(kpar) || ser32(index)
        const data = Buffer.allocUnsafe(1 + 32 + 4);
        data[0] = 0x00; // 1 bit
        this.privateKey.copy(data, 1); // 32 bits
        data.writeUInt32BE(index, 33); // 4 bits
        
        // create privateKey and chainCode
        const i = crypto.hmacSHA512(this.chainCode, data);
        const iL = i.slice(0, 32);
        const iR = i.slice(32);

        // check if key is valid 
        // while (!(new crypto.SECP256K1()).isValidPrivateKey(iL)) {

        //     // pad with 0x01 instead of increasing index
        // }
        let ret = new HDNode(iL, iR, undefined);
        ret.depth = this.depth + 1;
        return ret;
    }
}

function fromSeed(seed: Buffer, curve: crypto.CurveInfo): HDNode {
        // need to verify seed length is 512 bits
        let i = crypto.hmacSHA512(Buffer.from(curve.bip32Name, 'utf8'), seed);
        const iL = i.slice(0, 32);
        const iR = i.slice(32);
        let ret = new HDNode(iL, iR, undefined);
        ret.depth = 0;
        return ret;
    }

function main() {
    let node: HDNode = HDNode.fromSeed(Buffer.from(params.seed, 'hex'), crypto.SECP256K1);
    console.log(node.privateKey.toString('hex'));
    let child0 = node.derive(0 + HARDENED);
    console.log(child0.privateKey.toString('hex'));
}

main();
