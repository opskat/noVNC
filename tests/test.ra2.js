import RA2RecordCipher from '../core/ra2_cipher.js';

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
        expect(await receiver.open(changedLength)).to.equal(null);
    });

    it('should not advance the counter after failed authentication', async function () {
        const key = new Uint8Array(16).map((_, i) => i);
        const sender = await makeCipher(key);
        const receiver = await makeCipher(key);
        const record = await sender.seal(new Uint8Array([1, 2, 3]));
        const tampered = record.slice();
        tampered[tampered.length - 1] ^= 1;

        expect(await receiver.open(tampered)).to.equal(null);
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
