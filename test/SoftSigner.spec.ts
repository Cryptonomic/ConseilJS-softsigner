import { expect, use } from "chai";
import chaiAsPromised from 'chai-as-promised';
import { Signer, TezosMessageUtils } from 'conseiljs';

import { SoftSigner } from '../src/SoftSigner';
import { KeyStoreUtils } from '../src/KeyStoreUtils';

use(chaiAsPromised);

let signer: Signer;

describe('SoftSigner tests', () => {
    it('constructor', async () => {
        const keyStore = await KeyStoreUtils.restoreIdentityFromSecretKey('edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH');
        signer = new SoftSigner(TezosMessageUtils.writeKeyWithHint(keyStore.secretKey, 'edsk'));

        expect(signer).to.be.not.null;
    });

    it('sign', async () => {
        const result = await signer.signOperation(Buffer.from('Tacos Burritos', 'utf8'))
        const signature = TezosMessageUtils.readSignatureWithHint(result, 'edsig');

        expect(signature).to.equal('edsigtbmrgC8V2xU3Dc3n99v8CZk3cQAX1PcwbGRDkVkFSqax996qTPXsLryas9WBN9mCXiJFQSUiVkkkot6jQ4eEsU8rAt6jzW');
    });

    it('signText', async () => {
        const result = await signer.signText('Nachos Guacamole');

        expect(result).to.equal('edsigtgAgZNqK9JvihdDj4BduDaQYJR5vfca9pbowNDtc4aTRnbUcFv4YmJbQDBK9XpMnhntW26uSAHtEtpCo84Rt7jPg3iYXqY');
    });
});
