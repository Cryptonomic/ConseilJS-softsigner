import { expect, use } from "chai";
import chaiAsPromised from 'chai-as-promised';
import { SignerCurve, TezosMessageUtils } from 'conseiljs';

import { KeyStoreUtils } from '../src/KeyStoreUtils';

use(chaiAsPromised);

describe('KeyStoreUtils tests', () => {
    it('generateMnemonic 24-words', async () => {
        expect(KeyStoreUtils.generateMnemonic().split(' ').length).to.equal(24);
    });

    it('generateMnemonic 15-words', async () => {
        expect(KeyStoreUtils.generateMnemonic(160).split(' ').length).to.equal(15);
    });

    it('generateIdentity with default parameters', async () => {
        const result = await KeyStoreUtils.generateIdentity();

        expect(result.publicKeyHash).to.exist;
        expect(result.seed).to.exist;
    });

    it('generateIdentity with mnemonic', async () => {
        const result = await KeyStoreUtils.generateIdentity(0, '', 'slender young beauty smooth skin embrace firm body romance sleep head home');

        expect(result.publicKeyHash).to.equal('tz1UskuoYvJkkwnJ28gH3rfPirQbuDtRjfjc');
    });

    it('generateIdentity with mnemonic & password', async () => {
        const result = await KeyStoreUtils.generateIdentity(0, 'Nachos Tacos', 'resist winner shift attract issue penalty feed disease guess ridge grace warfare brave cause jar track exhibit movie seminar light broken light few tomato');

        expect(result.publicKeyHash).to.equal('tz1d6c6SVPfyoEodJqXNLPtknqoJMSRVYn8n');
    });

    it('restoreIdentityFromSecretKey', async () => {
        const result = await KeyStoreUtils.restoreIdentityFromSecretKey('edskRhLgG6p1qyj2Y1oitK1wspsHTQsHf7y8UKMxFDM53SDxRxWeSioqvUWQ8wPyTux4TTvg3nJT9WbXzBrcSCc3YVgsX3VwBy');

        expect(result.publicKeyHash).to.equal('tz1WRm1WMpioh4Gm1eopgvudaEoY6wX7cTTg');
    });

    it('restoreIdentityFromMnemonic', async () => {
        const result = await KeyStoreUtils.restoreIdentityFromMnemonic('resist winner shift attract issue penalty feed disease guess ridge grace warfare brave cause jar track exhibit movie seminar light broken light few tomato', 'Nachos Tacos', 'tz1d6c6SVPfyoEodJqXNLPtknqoJMSRVYn8n');

        expect(result.publicKeyHash).to.equal('tz1d6c6SVPfyoEodJqXNLPtknqoJMSRVYn8n');
    });

    it('restoreIdentityFromMnemonic, no validation', async () => {
        const result = await KeyStoreUtils.restoreIdentityFromMnemonic('resist winner shift attract issue penalty feed disease guess ridge grace warfare brave cause jar track exhibit movie seminar light broken light few tomato', 'Nachos Tacos', 'tz1d6c6SVPfyoEodJqXNLPtknqoJMSRVYn8n', undefined, false);

        expect(result.publicKeyHash).to.equal('tz1d6c6SVPfyoEodJqXNLPtknqoJMSRVYn8n');
    });

    it('restoreIdentityFromMnemonic fail verification', async () => {
        await expect(KeyStoreUtils.restoreIdentityFromMnemonic('resist winner shift attract issue penalty feed disease guess ridge grace warfare brave cause jar track exhibit movie seminar light broken light few tomato', 'Nachos Tacos', 'tz1WRm1WMpioh4Gm1eopgvudaEoY6wX7cTTg'))
            .to.be.rejectedWith('The given mnemonic and passphrase do not correspond to the supplied public key hash');
    });

    it('restoreIdentityFromMnemonic fail mnemonic length', async () => {
        await expect(KeyStoreUtils.restoreIdentityFromMnemonic('resist winner shift'))
            .to.be.rejectedWith('Invalid mnemonic length.');
    });

    it('restoreIdentityFromMnemonic fail mnemonic length', async () => {
        await expect(KeyStoreUtils.restoreIdentityFromMnemonic('coffee c0ffee c0ff33 coffee c0ffee c0ff33 coffee c0ffee c0ff33 coffee c0ffee c0ff33 coffee c0ffee c0ff33'))
            .to.be.rejectedWith('The given mnemonic could not be validated.');
    });

    it('restoreIdentityFromFundraiser', async () => {
        const faucetAccount = {
            mnemonic: [ "solve", "situate", "timber", "panther", "guide", "media", "dad", "style", "govern", "bracket", "hurry", "okay", "slide", "ripple", "rug" ],
            secret: "03e04299bb331d9855e1e0c86d684dceeff4f60e",
            amount: "32492613852",
            pkh: "tz1MRXFvJdkZdsr4CpGNB9dwA37LvMoNf7pM",
            password: "8PXlLLjH6e",
            email: "tsmnpgbq.ltvhiwzm@tezos.example.org"
        };

        const result = await KeyStoreUtils.restoreIdentityFromFundraiser(faucetAccount.mnemonic.join(' '), faucetAccount.email, faucetAccount.password, faucetAccount.pkh);
        expect(result.publicKeyHash).to.equal(faucetAccount.pkh);
    });

    it('encryptMessage', async () => {
        const message = 'Tezos Tacos Nachos Burritos';
        const salt = TezosMessageUtils.writeBufferWithHint('3xa4FZquGKYyT8542XKG3nsx7xN8');

        const result = await KeyStoreUtils.encryptMessage(Buffer.from(message, 'utf8'), 'Tezos', salt);

        expect(result).to.exist;
    });

    it('decryptMessage', async () => {
        const message = TezosMessageUtils.writeBufferWithHint('MhBgNSenyWP2xrBaMSBmdi9VSMHqtZvTAgBJRmyPpKmMoGZp6gJr2fKHHikzxeiuxFsnKJL6jQboXXqLX29ugpKT5QWyu6t9C');
        const salt = TezosMessageUtils.writeBufferWithHint('3xa4FZquGKYyT8542XKG3nsx7xN8');

        const result = await KeyStoreUtils.decryptMessage(message, 'Tezos', salt);

        expect(result.toString('utf8')).to.equal('Tezos Tacos Nachos Burritos');
    });

    it('checkTextSignature ED25519', async () => {
        const message = 'Tacos Burritos';
        const keyStore = await KeyStoreUtils.restoreIdentityFromSecretKey('edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH');
        const sig = 'edsigtbmrgC8V2xU3Dc3n99v8CZk3cQAX1PcwbGRDkVkFSqax996qTPXsLryas9WBN9mCXiJFQSUiVkkkot6jQ4eEsU8rAt6jzW';

        const result = await KeyStoreUtils.checkTextSignature(sig, message, keyStore.publicKey);

        expect(result).to.equal(true);
    });

    it('checkTextSignature ED25519, hashed', async () => {
        let publicKey = (await KeyStoreUtils.restoreIdentityFromSecretKey('edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH')).publicKey;
        let message = 'Tacos Burritos';
        let sig = 'edsigtmoSkpMujSVYXH6zxSaZyiH27qYscBezFWNnDohoBoKdmY9c4Jk8EhdNGok9riQGLu1MTnXM9y5om2cRAUCdFtXKQKp57f';
        let result = await KeyStoreUtils.checkTextSignature(sig, message, publicKey, true);
        expect(result).to.equal(true);

        publicKey = 'edpku976gpuAD2bXyx1XGraeKuCo1gUZ3LAJcHM12W1ecxZwoiu22R';
        message = 'test';
        sig = 'edsigtzLBGCyadERX1QsYHKpwnxSxEYQeGLnJGsSkHEsyY8vB5GcNdnvzUZDdFevJK7YZQ2ujwVjvQZn62ahCEcy74AwtbA8HuN';
        result = await KeyStoreUtils.checkTextSignature(sig, message, publicKey, true);
        expect(result).to.equal(true);
    });

    it('checkTextSignature SECP256K1', async () => {
        const message = 'Tacos Burritos';
        const publicKey = TezosMessageUtils.readKeyWithHint(Buffer.from('0366c4ad39716c06e1cb9348905d3743f236a8b97c5835ced80930dadf51bfbfdd', 'hex'), 'sppk');
        const sig = TezosMessageUtils.readSignatureWithHint(Buffer.from('e9a933ffaaf885bd345ddba87c6518e2a87e6827ab53cc112fbe415b83fc74cf437bc970ecdf2b886dc0005b6358ae04cc03de25cf841bc5fd1f1a525d9920ad', 'hex'), SignerCurve.SECP256K1);

        const result = await KeyStoreUtils.checkTextSignature(sig, message, publicKey, true);

        expect(result).to.equal(true);
    });

    it('checkSignature ED25519', async () => {
        const message = Buffer.from('057b22616c696173223a2274657374222c226465736372697074696f6e223a2274657374227d', 'hex');
        const publicKey = 'edpkvQ2i7NbUP4y1B1VBc9kiaiUu5n3Ps79bxyxCuYUCPcsxZ83rwS';
        const sig = 'edsigtiCcH17ciafZjVX6cX1p1ncZ7hK7BJSeauhZr6n2LN2yFmEoZCVbmhgXfy7NwAZ4Tj6Vf8SfpsxCBxPhi6SZXHLpuMw56Q';

        const result = await KeyStoreUtils.checkSignature(sig, message, publicKey, true);

        expect(result).to.equal(true);
    });
});
