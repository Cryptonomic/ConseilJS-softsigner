import { expect, use } from "chai";
import chaiAsPromised from 'chai-as-promised';
import { Signer, TezosMessageUtils } from 'conseiljs';

import { SoftSigner } from '../src/SoftSigner';
import { KeyStoreUtils } from '../src/KeyStoreUtils';

use(chaiAsPromised);

let signer: Signer;

describe('SoftSigner tests', () => {
    it('constructor without key encryption', async () => {
        const keyStore = await KeyStoreUtils.restoreIdentityFromSecretKey('edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH');
        
        signer = await SoftSigner.createSigner(TezosMessageUtils.writeKeyWithHint(keyStore.secretKey, 'edsk'), -1);

        expect(signer).to.be.not.null;
    });

    it('constructor with key encryption', async () => {
        const keyStore = await KeyStoreUtils.restoreIdentityFromSecretKey('edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH');
        
        signer = await SoftSigner.createSigner(TezosMessageUtils.writeKeyWithHint(keyStore.secretKey, 'edsk'), 5);
        await (new Promise(resolve => setTimeout(resolve, 6000)));

        expect(signer).to.be.not.null;
    });

    it('sign', async () => {
        const forgedOperationGroup = 'f58c43b69cf5fa7e6183ea3d899a480c9b5b3d6dadea68ee2e5c21ae1cc767ab6c0034a00f9b7964943b4ab583a8d1f7241a0cb9742cd20be807904eac02e80700002c0b1b21166a60a985fd8f11b567c445382fbd8300';
        const result = await signer.signOperation(Buffer.from('03' + forgedOperationGroup, 'hex'));
        const signature = TezosMessageUtils.readSignatureWithHint(result, 'edsig');

        expect(signature).to.equal('edsigtyUK6MFziVBFXmEEnc1TuFsmcCCrke5nVG2uWLh4y1ydPFweD1C7Q4MDUqHQXkwEVwDmBMfp2ufc3MRi9MRM7kETd4vgnZ');
    });

    it('signText', async () => {
        const result = await signer.signText('Nachos Guacamole');

        expect(result).to.equal('edsigtgAgZNqK9JvihdDj4BduDaQYJR5vfca9pbowNDtc4aTRnbUcFv4YmJbQDBK9XpMnhntW26uSAHtEtpCo84Rt7jPg3iYXqY');
    });

    it('signTextHash', async () => {
        const result = await signer.signTextHash('Nachos Guacamole');

        expect(result).to.equal('edsigtnrQesbWjnoKmKYZZR9dSJYwkWMJw4rEq9xwRuehEhXzk1tCmvCAnTEgCE1zaYhpPHpECYapufEtFBSkj4vCSj1gKJLnZN');
    });
});
