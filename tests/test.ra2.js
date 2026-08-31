import RSAAESAuthenticationState from '../core/ra2.js';
import RA2RecordCipher, { RA2CipherError } from '../core/ra2_cipher.js';
import legacyCrypto from '../core/crypto/crypto.js';

function fromHex(value) {
    return new Uint8Array(value.match(/../g).map(byte => parseInt(byte, 16)));
}

async function expectRejected(promise, message) {
    let error;
    try {
        await promise;
    } catch (err) {
        error = err;
    }
    expect(error).to.be.an.instanceOf(Error);
    if (message !== undefined) {
        expect(error.message).to.contain(message);
    }
}

describe('RSA-AES authentication variants', function () {
    "use strict";

    const variants = [
        { type: 5, name: 'RA2', aesBits: 128, sessionEncrypted: true, rekey: false },
        { type: 6, name: 'RA2ne', aesBits: 128, sessionEncrypted: false, rekey: false },
        { type: 13, name: 'RA2r', aesBits: 128, sessionEncrypted: true, rekey: true },
        { type: 129, name: 'RA2_256', aesBits: 256, sessionEncrypted: true, rekey: false },
        { type: 130, name: 'RA2ne_256', aesBits: 256, sessionEncrypted: false, rekey: false },
        { type: 133, name: 'RA2r_256', aesBits: 256, sessionEncrypted: true, rekey: true },
    ];

    class FakeRA2Socket {
        constructor() {
            this._receiveQueue = [];
            this._sendQueue = [];
            this.sent = [];
            this.activations = [];
        }

        receive(data) {
            this._receiveQueue.push(...data);
        }

        rQwait(_label, length) {
            return this._receiveQueue.length < length;
        }

        rQpeekBytes(length) {
            return new Uint8Array(this._receiveQueue.slice(0, length));
        }

        rQshift16() {
            return (this._receiveQueue.shift() << 8) | this._receiveQueue.shift();
        }

        rQshift32() {
            return ((this._receiveQueue.shift() << 24) |
                    (this._receiveQueue.shift() << 16) |
                    (this._receiveQueue.shift() << 8) |
                    this._receiveQueue.shift()) >>> 0;
        }

        rQshiftBytes(length) {
            return new Uint8Array(this._receiveQueue.splice(0, length));
        }

        sQpushBytes(data) {
            this._sendQueue.push(...data);
        }

        flush() {
            if (this._sendQueue.length !== 0) {
                this.sent.push(new Uint8Array(this._sendQueue));
                this._sendQueue = [];
            }
            return Promise.resolve();
        }

        activateTransportTransform(sendCipher, receiveCipher) {
            this.activations.push({
                sendCipher,
                receiveCipher,
                sentCount: this.sent.length,
            });
            return Promise.resolve();
        }
    }

    function concat(...arrays) {
        const result = new Uint8Array(arrays.reduce((sum, value) => sum + value.length, 0));
        let offset = 0;
        for (const value of arrays) {
            result.set(value, offset);
            offset += value.length;
        }
        return result;
    }

    function encodedKey(bits, modulusByte) {
        const bytes = bits / 8;
        const key = new Uint8Array(4 + bytes * 2);
        key[0] = (bits >>> 24) & 0xff;
        key[1] = (bits >>> 16) & 0xff;
        key[2] = (bits >>> 8) & 0xff;
        key[3] = bits & 0xff;
        key.fill(modulusByte, 4, 4 + bytes);
        key[key.length - 3] = 1;
        key[key.length - 1] = 1;
        return key;
    }

    async function digest(algorithm, ...arrays) {
        return new Uint8Array(await window.crypto.subtle.digest(
            algorithm, concat(...arrays)));
    }

    async function makeCipher(key) {
        const cipher = new RA2RecordCipher();
        await cipher.setKey(key);
        return cipher;
    }

    async function waitFor(state, predicate) {
        for (let i = 0; i < 100; i++) {
            state.checkInternalEvents();
            if (predicate()) {
                return;
            }
            await new Promise(resolve => setTimeout(resolve, 0));
        }
        throw new Error('Timed out waiting for RSA-AES handshake');
    }

    async function feed(state, sock, data) {
        sock.receive(data);
        await waitFor(state, () => sock._receiveQueue.length === 0);
        await new Promise(resolve => setTimeout(resolve, 0));
    }

    async function runHandshake(variant, approveImmediately = true,
                                completeRekey = true) {
        const randomBytes = variant.aesBits / 8;
        const hashAlgorithm = variant.aesBits === 128 ? 'SHA-1' : 'SHA-256';
        const serverPublicKey = encodedKey(1024, 0x51);
        const clientPublicKey = encodedKey(2048, 0x61);
        const clientRandom = new Uint8Array(randomBytes).fill(0x11);
        const serverRandom = new Uint8Array(randomBytes).fill(0x22);
        const replacementClientRandom = new Uint8Array(randomBytes).fill(0x33);
        const replacementServerRandom = new Uint8Array(randomBytes).fill(0x44);
        const generatedRandoms = [];
        let decryptResult = serverRandom;

        const originalImportKey = legacyCrypto.importKey.bind(legacyCrypto);
        sinon.stub(legacyCrypto, 'importKey').callsFake(
            (format, keyData, algorithm, extractable, keyUsages) => {
                if (algorithm.name === 'RSA-PKCS1-v1_5') {
                    return Promise.resolve({ rsa: true });
                }
                return originalImportKey(format, keyData, algorithm, extractable, keyUsages);
            });
        sinon.stub(legacyCrypto, 'generateKey').resolves({ privateKey: { rsa: true } });
        sinon.stub(legacyCrypto, 'exportKey').resolves({
            n: clientPublicKey.slice(4, 260),
            e: clientPublicKey.slice(260),
        });
        sinon.stub(legacyCrypto, 'encrypt').callsFake((algorithm, key, data) => {
            if (algorithm.name === 'RSA-PKCS1-v1_5') {
                return Promise.resolve(new Uint8Array(128));
            }
            return key.encrypt(algorithm, data);
        });
        sinon.stub(legacyCrypto, 'decrypt').callsFake((algorithm, key, data) => {
            if (algorithm.name === 'RSA-PKCS1-v1_5') {
                return Promise.resolve(decryptResult);
            }
            return key.decrypt(algorithm, data);
        });
        sinon.stub(window.crypto, 'getRandomValues').callsFake((array) => {
            const value = generatedRandoms.length === 0 ? clientRandom : replacementClientRandom;
            array.set(value);
            generatedRandoms.push(array.slice());
            return array;
        });

        const sock = new FakeRA2Socket();
        const state = new RSAAESAuthenticationState(
            sock, () => ({ username: 'user', password: 'pass' }), variant.type);
        let verification = false;
        state.addEventListener('serververification', () => {
            verification = true;
            if (approveImmediately) {
                state.approveServer();
            }
        });
        const negotiation = state.negotiateAuthAsync();

        await feed(state, sock, serverPublicKey);
        await waitFor(state, () => verification);

        const result = {
            state,
            sock,
            negotiation,
            approve() { state.approveServer(); },
            generatedRandoms,
            serverPublicKey,
            clientPublicKey,
            clientRandom,
            serverRandom,
            replacementClientRandom,
            replacementServerRandom,
            hashAlgorithm,
            setDecryptResult(value) { decryptResult = value; },
        };
        if (!approveImmediately) {
            return result;
        }

        await waitFor(state, () => sock.sent.length === 2);
        const encryptedServerRandom = new Uint8Array(258);
        encryptedServerRandom[0] = 1;
        await feed(state, sock, encryptedServerRandom);

        const clientKey = (await digest(hashAlgorithm, serverRandom, clientRandom)).slice(0, randomBytes);
        const serverKey = (await digest(hashAlgorithm, clientRandom, serverRandom)).slice(0, randomBytes);
        const clientCipher = await makeCipher(clientKey);
        const serverCipher = await makeCipher(serverKey);
        const serverHash = await digest(hashAlgorithm, serverPublicKey, clientPublicKey);

        await waitFor(state, () => sock.sent.length === 3);
        expect(await clientCipher.open(sock.sent[2])).to.array.equal(
            await digest(hashAlgorithm, clientPublicKey, serverPublicKey));
        await feed(state, sock, await serverCipher.seal(serverHash));
        await feed(state, sock, await serverCipher.seal(new Uint8Array([1])));
        await waitFor(state, () => sock.sent.length >= 4);
        expect(await clientCipher.open(sock.sent[3])).to.array.equal(
            new Uint8Array([4, 117, 115, 101, 114, 4, 112, 97, 115, 115]));

        result.clientCipher = clientCipher;
        result.serverCipher = serverCipher;
        if (variant.rekey) {
            await waitFor(state, () => sock.sent.length === 5);
            expect(await clientCipher.open(sock.sent[4])).to.array.equal(replacementClientRandom);
            if (!completeRekey) {
                return result;
            }
            await feed(state, sock, await serverCipher.seal(replacementServerRandom));
        }
        await negotiation;
        return result;
    }

    afterEach(function () {
        sinon.restore();
    });

    for (const variant of variants) {
        it(`negotiates ${variant.name} with the correct transcript sizes and activation`, async function () {
            const result = await runHandshake(variant);
            const randomBytes = variant.aesBits / 8;

            expect(result.generatedRandoms[0]).to.have.length(randomBytes);
            expect(result.sock.sent[2]).to.have.length(
                2 + (variant.aesBits === 128 ? 20 : 32) + 16);
            expect(result.state.securityDetails).to.deep.equal({
                type: variant.type,
                name: variant.name,
                authenticationEncrypted: true,
                sessionEncrypted: variant.sessionEncrypted,
                aesBits: variant.aesBits,
            });
            expect(result.sock.activations).to.have.length(variant.sessionEncrypted ? 1 : 0);
            expect(result.state._clientCipher).to.equal(null);
            expect(result.state._serverCipher).to.equal(null);

            if (variant.sessionEncrypted) {
                const active = result.sock.activations[0];
                expect(active.sentCount).to.equal(variant.rekey ? 5 : 4);
                let clientKey;
                let serverKey;
                if (variant.rekey) {
                    clientKey = await digest(result.hashAlgorithm,
                                             result.replacementServerRandom,
                                             result.replacementClientRandom);
                    serverKey = await digest(result.hashAlgorithm,
                                             result.replacementClientRandom,
                                             result.replacementServerRandom);
                } else {
                    clientKey = await digest(result.hashAlgorithm,
                                             result.serverRandom, result.clientRandom);
                    serverKey = await digest(result.hashAlgorithm,
                                             result.clientRandom, result.serverRandom);
                }
                clientKey = clientKey.slice(0, randomBytes);
                serverKey = serverKey.slice(0, randomBytes);

                const expectedClient = await makeCipher(clientKey);
                const expectedServer = await makeCipher(serverKey);
                if (!variant.rekey) {
                    await expectedClient.seal(new Uint8Array(
                        variant.aesBits === 128 ? 20 : 32));
                    await expectedClient.seal(new Uint8Array(10));
                    await expectedServer.seal(new Uint8Array(
                        variant.aesBits === 128 ? 20 : 32));
                    await expectedServer.seal(new Uint8Array([1]));
                }
                const outbound = new Uint8Array([9, 8, 7]);
                expect(await active.sendCipher.seal(outbound)).to.array.equal(
                    await expectedClient.seal(outbound));
                const securityResult = new Uint8Array([0, 0, 0, 0]);
                expect(await active.receiveCipher.open(
                    await expectedServer.seal(securityResult))).to.array.equal(securityResult);
            }
        });
    }

    it('does not send handshake secrets before server-key approval', async function () {
        const result = await runHandshake(variants[0], false);

        expect(result.sock.sent).to.have.length(0);
        result.approve();
        await waitFor(result.state, () => result.sock.sent.length === 2);
        expect(result.generatedRandoms).to.have.length(1);
        result.state.disconnect();
        await expectRejected(result.negotiation, 'disconnect normally');
    });

    it('does not continue a pending handshake after disconnect', async function () {
        const result = await runHandshake(variants[0], false);

        result.state.disconnect();
        await expectRejected(result.negotiation, 'disconnect normally');
        expect(result.sock.sent).to.have.length(0);
    });

    it('fails closed if the RA2r replacement random is not authenticated', async function () {
        const result = await runHandshake(variants[2], true, false);
        const tampered = await result.serverCipher.seal(result.replacementServerRandom);
        tampered[tampered.length - 1] ^= 1;

        await feed(result.state, result.sock, tampered);
        await expectRejected(result.negotiation, 'authenticate');
        expect(result.sock.activations).to.have.length(0);
    });
});

describe('RA2RecordCipher', function () {
    "use strict";

    async function makeCipher(key) {
        const cipher = new RA2RecordCipher();
        await cipher.setKey(key);
        return cipher;
    }

    it('should seal the AES-128 record vector with an authenticated length', async function () {
        const cipher = await makeCipher(new Uint8Array(16).map((_, i) => i));
        const record = await cipher.seal(new Uint8Array([1, 2, 3]));

        expect(record).to.array.equal(fromHex('0003799e45e0228ffc4ce3db47e0ed3c01ee947beb'));
    });

    it('should seal the AES-256 record vector', async function () {
        const cipher = await makeCipher(new Uint8Array(32).map((_, i) => i));
        const record = await cipher.seal(new Uint8Array([1, 2, 3]));

        expect(record).to.array.equal(fromHex('0003d45fe686a1a93503a16b315aea610640c4f88e'));
    });

    it('should reject malformed records and authenticated length changes', async function () {
        const key = new Uint8Array(16).map((_, i) => i);
        const sender = await makeCipher(key);
        const receiver = await makeCipher(key);
        const record = await sender.seal(new Uint8Array([1, 2, 3]));
        const changedLength = new Uint8Array(record.length + 1);
        changedLength.set(record);
        changedLength[1] = 4;

        await expectRejected(receiver.open(record.slice(0, -1)), 'length');
        await expectRejected(receiver.open(changedLength), 'authenticate');
    });

    it('should reject failed authentication with a typed integrity error without advancing the counter', async function () {
        const key = new Uint8Array(16).map((_, i) => i);
        const sender = await makeCipher(key);
        const receiver = await makeCipher(key);
        const record = await sender.seal(new Uint8Array([1, 2, 3]));
        const tampered = record.slice();
        tampered[tampered.length - 1] ^= 1;
        let failure;

        try {
            await receiver.open(tampered);
        } catch (error) {
            failure = error;
        }

        expect(failure).to.be.instanceOf(RA2CipherError);
        expect(failure.failureCode).to.equal('integrity-failed');
        expect(await receiver.open(record)).to.array.equal(new Uint8Array([1, 2, 3]));
    });

    it('should increment the 128-bit counter in little-endian order with carry', async function () {
        const cipher = await makeCipher(new Uint8Array(16).map((_, i) => i));
        let record;
        for (let counter = 0; counter <= 256; counter++) {
            record = await cipher.seal(new Uint8Array([0xaa]));
            if (counter === 255) {
                expect(record).to.array.equal(
                    fromHex('0001e22706940c61b56cba8b7a529b0f57b28e'));
            }
        }

        expect(record).to.array.equal(fromHex('0001d61ef587810d608444a0e402aad069b824'));
    });

    it('should serialize concurrent operations without reusing a counter', async function () {
        const cipher = await makeCipher(new Uint8Array(16).map((_, i) => i));
        const records = await Promise.all([
            cipher.seal(new Uint8Array([0xaa])),
            cipher.seal(new Uint8Array([0xaa])),
        ]);

        expect(records[0]).to.array.equal(fromHex('0001d243f70bbb701595b757478a269fefac82'));
        expect(records[1]).to.array.equal(fromHex('00014a86de5cc215a2d3610e36c00ac25deaaa'));
    });

    it('should reset the record counter', async function () {
        const cipher = await makeCipher(new Uint8Array(16).map((_, i) => i));
        const first = await cipher.seal(new Uint8Array([0xaa]));
        cipher.reset();

        expect(await cipher.seal(new Uint8Array([0xaa]))).to.array.equal(first);
    });
});
