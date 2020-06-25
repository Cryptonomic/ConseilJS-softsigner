import * as crypto from './crypto';

import * as tests from './tests.json';

const HARDENED = 0x80000000;

function BIP32Path(value: string): boolean {
  return (
      /*typeforce.String(value) && */
      value.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null);
}

// https://github.com/satoshilabs/slips/blob/master/slip-0010.md
class HDNode {
    privateKey: Buffer;
    chainCode: Buffer;
    publicKey: Buffer | undefined;
    index: number;
    depth: number;

    constructor(privateKey: Buffer, chainCode: Buffer, publicKey: Buffer | undefined) {
        this.privateKey = privateKey;
        this.chainCode = chainCode;
        this.publicKey = publicKey;
    }

    static fromSeed(seed: Buffer, curve: crypto.CurveInfo): HDNode {
        // need to verify seed length is 512 bits
        let i = crypto.hmacSHA512(Buffer.from(curve.bip32Name, 'utf8'), seed);
        const iL = i.slice(0, 32);
        const iR = i.slice(32);
        let ret = new HDNode(iL, iR, undefined);
        ret.depth = 0;
        return ret;
    }

    isNeutered(): boolean {
        return this.privateKey === undefined;
    }

    derive(index: number): HDNode {
        // only support curve ed25519 - hardened derivation required
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

        let child = new HDNode(iL, iR, undefined);
        child.depth = this.depth + 1;
        return child;
    }

    derivePath(path: string): HDNode {
        if (!BIP32Path(path))
            throw "Invalid derivation path";

        let splitPath = path.split('/').slice(1);

        return splitPath.reduce(
            (prevHDNode, indexStr) => {
            let index;
            if (indexStr.slice(-1) === `'`) {
                index = parseInt(indexStr.slice(0, -1), 10);
                return prevHDNode.derive(index+HARDENED);
            } else {
                // only support ED25519 - require hardened derivation
                throw "Unhardened derivation unsupported";
            }
            },
            this as HDNode,
        );
    }
}

async function main() {
    // // get pubkey from ledger
    // let ledger = await ledgersigner.TezosLedgerConnector.getInstance();
    // console.log(await ledger.getAddress(derivationPath, true, ledgersigner.Curve.SECP256K1));
    // console.log("ledger\n" + (await ledgerKeyStore.getTezosPublicKey(derivationPath)));

    // just stored this in a const above
    // let seed = (await bip39.mnemonicToSeed(mnemonic, passphrase)).toString("hex");
    // console.log(seed);

    // let bip32Node = bip32.fromSeed(Buffer.from(seed, 'utf8'));

    let node: HDNode = HDNode.fromSeed(Buffer.from(tests.ed25519[0].seed, 'hex'), crypto.ED25519);
    console.log(`Master derivation:\n\tExpected: ${tests.ed25519[0].derivations[0].private}\n\tResult: ${node.privateKey.toString('hex')}`);
    // let child0 = node.derive(0 + HARDENED);
    // console.log(`Child0 derivation:\n\tExpected: ${tests.ed25519[0].derivations[1].private}\n\tResult: ${child0.privateKey.toString('hex')}`);
    let child01 = node.derivePath(tests.ed25519[0].derivations[2].path);
    console.log(`Child01 derivation:\n\tExpected: ${tests.ed25519[0].derivations[2].private}\n\tResult: ${child01.privateKey.toString('hex')}`);
}

main();
