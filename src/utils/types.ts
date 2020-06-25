export interface HDNode {
    readonly privateKey: Buffer;
    readonly chainCode: Buffer;
    readonly publicKey: Buffer | undefined;
    readonly index: number | undefined; // undefined for master node
    readonly depth: number;
    readonly curve: CurveInfo;
}

export enum BIP32Name {
    SECP256K1 = "Bitcoin seed",
    ED25519 = "ed25519 seed",
    NISTP256 = "Nist256p1 seed"
}

export interface CurveInfo {
    bip32Name: BIP32Name;
    publicKey(privateKey: Buffer): Promise<Buffer>;
}
