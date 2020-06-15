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
        const result = await signer.sign(Buffer.from('Tacos Burritos', 'utf8'))
        const signature = TezosMessageUtils.readSignatureWithHint(result, 'edsig');

        expect(signature).to.equal('edsigtmoSkpMujSVYXH6zxSaZyiH27qYscBezFWNnDohoBoKdmY9c4Jk8EhdNGok9riQGLu1MTnXM9y5om2cRAUCdFtXKQKp57f');
    });

    it('signText', async () => {
        const result = await signer.signText('Nachos Guacamole');

        expect(result).to.equal('edsigtnrQesbWjnoKmKYZZR9dSJYwkWMJw4rEq9xwRuehEhXzk1tCmvCAnTEgCE1zaYhpPHpECYapufEtFBSkj4vCSj1gKJLnZN');
    });
});
