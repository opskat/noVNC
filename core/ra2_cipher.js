import legacyCrypto from './crypto/crypto.js';

export const RA2_RECORD_MAX_PLAINTEXT = 8192;
const RA2_RECORD_TAG_LENGTH = 16;
const RA2_RECORD_HEADER_LENGTH = 2;

export class RA2RecordCipher {
    constructor() {
        this._cipher = null;
        this._counter = new Uint8Array(16);
        this._generation = 0;
        this._operation = Promise.resolve();
    }

    async setKey(key) {
        this._cipher = await legacyCrypto.importKey(
            "raw", key, { name: "AES-EAX" }, false, ["encrypt", "decrypt"]);
        this.reset();
    }

    reset() {
        this._generation++;
        this._counter.fill(0);
    }

    seal(plaintext) {
        if (this._cipher === null) {
            return Promise.reject(new Error("RA2 record cipher has no key"));
        }
        if (plaintext.length > RA2_RECORD_MAX_PLAINTEXT) {
            return Promise.reject(new Error("RA2 record plaintext is too long"));
        }

        const message = new Uint8Array(plaintext);
        const generation = this._generation;
        return this._serialize(async () => {
            this._checkGeneration(generation);
            const header = this._makeHeader(message.length);
            const encrypted = await legacyCrypto.encrypt({
                name: "AES-EAX",
                iv: this._counter.slice(),
                additionalData: header,
            }, this._cipher, message);
            this._checkGeneration(generation);

            const record = new Uint8Array(
                RA2_RECORD_HEADER_LENGTH + message.length + RA2_RECORD_TAG_LENGTH);
            record.set(header);
            record.set(encrypted, RA2_RECORD_HEADER_LENGTH);
            this._incrementCounter();
            return record;
        });
    }

    open(record) {
        if (this._cipher === null) {
            return Promise.reject(new Error("RA2 record cipher has no key"));
        }

        const data = new Uint8Array(record);
        if (data.length < RA2_RECORD_HEADER_LENGTH + RA2_RECORD_TAG_LENGTH) {
            return Promise.reject(new Error("RA2 record has a malformed length"));
        }
        const length = (data[0] << 8) | data[1];
        if (length > RA2_RECORD_MAX_PLAINTEXT ||
            data.length !== RA2_RECORD_HEADER_LENGTH + length + RA2_RECORD_TAG_LENGTH) {
            return Promise.reject(new Error("RA2 record has a malformed length"));
        }

        const generation = this._generation;
        return this._serialize(async () => {
            this._checkGeneration(generation);
            const plaintext = await legacyCrypto.decrypt({
                name: "AES-EAX",
                iv: this._counter.slice(),
                additionalData: data.subarray(0, RA2_RECORD_HEADER_LENGTH),
            }, this._cipher, data.subarray(RA2_RECORD_HEADER_LENGTH));
            this._checkGeneration(generation);
            if (plaintext !== null) {
                this._incrementCounter();
            }
            return plaintext;
        });
    }

    _serialize(operation) {
        const result = this._operation.then(operation);
        this._operation = result.catch(() => {});
        return result;
    }

    _checkGeneration(generation) {
        if (generation !== this._generation) {
            throw new Error("RA2 record cipher was reset during an operation");
        }
    }

    _makeHeader(length) {
        return new Uint8Array([length >>> 8, length & 0xff]);
    }

    _incrementCounter() {
        for (let i = 0; i < this._counter.length; i++) {
            this._counter[i]++;
            if (this._counter[i] !== 0) {
                break;
            }
        }
    }
}

export default RA2RecordCipher;
