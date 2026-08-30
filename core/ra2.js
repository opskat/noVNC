import { encodeUTF8 } from './util/strings.js';
import EventTargetMixin from './util/eventtarget.js';
import legacyCrypto from './crypto/crypto.js';
import RA2RecordCipher from './ra2_cipher.js';

const RA2_VARIANTS = {
    5: {
        name: 'RA2',
        aesBits: 128,
        sessionEncrypted: true,
        rekey: false,
    },
    6: {
        name: 'RA2ne',
        aesBits: 128,
        sessionEncrypted: false,
        rekey: false,
    },
    13: {
        name: 'RA2r',
        aesBits: 128,
        sessionEncrypted: true,
        rekey: true,
    },
    129: {
        name: 'RA2_256',
        aesBits: 256,
        sessionEncrypted: true,
        rekey: false,
    },
    130: {
        name: 'RA2ne_256',
        aesBits: 256,
        sessionEncrypted: false,
        rekey: false,
    },
    133: {
        name: 'RA2r_256',
        aesBits: 256,
        sessionEncrypted: true,
        rekey: true,
    },
};

export default class RSAAESAuthenticationState extends EventTargetMixin {
    constructor(sock, getCredentials, securityType = 6) {
        super();
        if (!(securityType in RA2_VARIANTS)) {
            throw new Error("RA2: unsupported security type: " + securityType);
        }

        const variant = RA2_VARIANTS[securityType];
        this._hasStarted = false;
        this._checkSock = null;
        this._checkCredentials = null;
        this._approveServerResolve = null;
        this._sockReject = null;
        this._credentialsReject = null;
        this._approveServerReject = null;
        this._sock = sock;
        this._getCredentials = getCredentials;
        this._randomBytes = variant.aesBits / 8;
        this._hashAlgorithm = variant.aesBits === 128 ? "SHA-1" : "SHA-256";
        this._hashBytes = variant.aesBits === 128 ? 20 : 32;
        this._rekey = variant.rekey;
        this._securityDetails = Object.freeze({
            type: securityType,
            name: variant.name,
            authenticationEncrypted: true,
            sessionEncrypted: variant.sessionEncrypted,
            aesBits: variant.aesBits,
        });
        this._clientCipher = null;
        this._serverCipher = null;
        this._disconnected = false;
    }

    _waitSockAsync(len) {
        return new Promise((resolve, reject) => {
            if (this._disconnected) {
                reject(new Error("disconnect normally"));
                return;
            }
            const hasData = () => !this._sock.rQwait('RA2', len);
            if (hasData()) {
                resolve();
            } else {
                this._checkSock = () => {
                    if (hasData()) {
                        resolve();
                        this._checkSock = null;
                        this._sockReject = null;
                    }
                };
                this._sockReject = reject;
            }
        });
    }

    _waitApproveKeyAsync() {
        return new Promise((resolve, reject) => {
            if (this._disconnected) {
                reject(new Error("disconnect normally"));
                return;
            }
            this._approveServerResolve = resolve;
            this._approveServerReject = reject;
        });
    }

    _waitCredentialsAsync(subtype) {
        const hasCredentials = () => {
            if (subtype === 1 && this._getCredentials().username !== undefined &&
                this._getCredentials().password !== undefined) {
                return true;
            } else if (subtype === 2 && this._getCredentials().password !== undefined) {
                return true;
            }
            return false;
        };
        return new Promise((resolve, reject) => {
            if (this._disconnected) {
                reject(new Error("disconnect normally"));
            } else if (hasCredentials()) {
                resolve();
            } else {
                this._checkCredentials = () => {
                    if (hasCredentials()) {
                        resolve();
                        this._checkCredentials = null;
                        this._credentialsReject = null;
                    }
                };
                this._credentialsReject = reject;
            }
        });
    }

    async _digest(...values) {
        const length = values.reduce((sum, value) => sum + value.length, 0);
        const input = new Uint8Array(length);
        let offset = 0;
        for (const value of values) {
            input.set(value, offset);
            offset += value.length;
        }
        return new Uint8Array(await window.crypto.subtle.digest(
            this._hashAlgorithm, input));
    }

    async _makeCipher(key) {
        const cipher = new RA2RecordCipher();
        await cipher.setKey(key);
        return cipher;
    }

    async _deriveCiphers(clientRandom, serverRandom) {
        const clientKey = (await this._digest(serverRandom, clientRandom)).slice(
            0, this._randomBytes);
        const serverKey = (await this._digest(clientRandom, serverRandom)).slice(
            0, this._randomBytes);
        return {
            clientCipher: await this._makeCipher(clientKey),
            serverCipher: await this._makeCipher(serverKey),
        };
    }

    async _openRecord(cipher, expectedLength, description) {
        await this._waitSockAsync(2);
        const header = this._sock.rQpeekBytes(2);
        const length = (header[0] << 8) | header[1];
        if (length !== expectedLength) {
            throw new Error("RA2: wrong " + description);
        }
        await this._waitSockAsync(2 + length + 16);
        const plaintext = await cipher.open(
            this._sock.rQshiftBytes(2 + length + 16));
        this._checkConnected();
        if (plaintext === null) {
            throw new Error("RA2: failed to authenticate the message");
        }
        return plaintext;
    }

    async _readEncryptedRandom(clientRSACipher, clientKeyBytes) {
        await this._waitSockAsync(2);
        const header = this._sock.rQpeekBytes(2);
        const length = (header[0] << 8) | header[1];
        if (length !== clientKeyBytes) {
            throw new Error("RA2: wrong encrypted message length");
        }
        await this._waitSockAsync(2 + length);
        this._sock.rQshiftBytes(2);
        const encrypted = this._sock.rQshiftBytes(length);
        const random = await legacyCrypto.decrypt(
            { name: "RSA-PKCS1-v1_5" }, clientRSACipher, encrypted);
        this._checkConnected();
        if (random === null || random.length !== this._randomBytes) {
            throw new Error("RA2: corrupted server encrypted random");
        }
        return random;
    }

    _makeCredentials(subtype) {
        let username;
        if (subtype === 1) {
            username = encodeUTF8(this._getCredentials().username).slice(0, 255);
        } else {
            username = "";
        }
        const password = encodeUTF8(this._getCredentials().password).slice(0, 255);
        const credentials = new Uint8Array(username.length + password.length + 2);
        credentials[0] = username.length;
        credentials[username.length + 1] = password.length;
        for (let i = 0; i < username.length; i++) {
            credentials[i + 1] = username.charCodeAt(i);
        }
        for (let i = 0; i < password.length; i++) {
            credentials[username.length + 2 + i] = password.charCodeAt(i);
        }
        return credentials;
    }

    async _waitForCredentials(subtype) {
        if (subtype !== 1 && subtype !== 2) {
            throw new Error("RA2: wrong subtype");
        }
        const waitCredentials = this._waitCredentialsAsync(subtype);
        if (subtype === 1) {
            if (this._getCredentials().username === undefined ||
                this._getCredentials().password === undefined) {
                this.dispatchEvent(new CustomEvent(
                    'credentialsrequired',
                    { detail: { types: ['username', 'password'] } }));
            }
        } else if (subtype === 2) {
            if (this._getCredentials().password === undefined) {
                this.dispatchEvent(new CustomEvent(
                    'credentialsrequired',
                    { detail: { types: ['password'] } }));
            }
        }
        await waitCredentials;
    }

    _checkConnected() {
        if (this._disconnected) {
            throw new Error("disconnect normally");
        }
    }

    checkInternalEvents() {
        if (this._checkSock !== null) {
            this._checkSock();
        }
        if (this._checkCredentials !== null) {
            this._checkCredentials();
        }
    }

    approveServer() {
        if (this._approveServerResolve !== null) {
            this._approveServerResolve();
            this._approveServerResolve = null;
            this._approveServerReject = null;
        }
    }

    _discardCiphers() {
        if (this._clientCipher !== null) {
            this._clientCipher.reset();
            this._clientCipher = null;
        }
        if (this._serverCipher !== null) {
            this._serverCipher.reset();
            this._serverCipher = null;
        }
    }

    disconnect() {
        this._disconnected = true;
        this._discardCiphers();
        if (this._sockReject !== null) {
            this._sockReject(new Error("disconnect normally"));
            this._sockReject = null;
        }
        this._checkSock = null;
        if (this._credentialsReject !== null) {
            this._credentialsReject(new Error("disconnect normally"));
            this._credentialsReject = null;
        }
        this._checkCredentials = null;
        if (this._approveServerReject !== null) {
            this._approveServerReject(new Error("disconnect normally"));
            this._approveServerReject = null;
        }
        this._approveServerResolve = null;
    }

    async _negotiateAuthAsync() {
        // 1: Receive and approve the server public key before sending secrets
        await this._waitSockAsync(4);
        const serverKeyLengthBuffer = this._sock.rQpeekBytes(4);
        const serverKeyLength = this._sock.rQshift32();
        if (serverKeyLength < 1024) {
            throw new Error("RA2: server public key is too short: " + serverKeyLength);
        } else if (serverKeyLength > 8192) {
            throw new Error("RA2: server public key is too long: " + serverKeyLength);
        }
        const serverKeyBytes = Math.ceil(serverKeyLength / 8);
        await this._waitSockAsync(serverKeyBytes * 2);
        const serverN = this._sock.rQshiftBytes(serverKeyBytes);
        const serverE = this._sock.rQshiftBytes(serverKeyBytes);
        const serverRSACipher = await legacyCrypto.importKey(
            'raw', { n: serverN, e: serverE },
            { name: 'RSA-PKCS1-v1_5' }, false, ['encrypt']);
        this._checkConnected();
        const serverPublicKey = new Uint8Array(4 + serverKeyBytes * 2);
        serverPublicKey.set(serverKeyLengthBuffer);
        serverPublicKey.set(serverN, 4);
        serverPublicKey.set(serverE, 4 + serverKeyBytes);

        const approveKey = this._waitApproveKeyAsync();
        this.dispatchEvent(new CustomEvent('serververification', {
            detail: { type: 'RSA', publickey: serverPublicKey }
        }));
        await approveKey;
        this._checkConnected();

        // 2: Send client public key
        const clientKeyLength = 2048;
        const clientKeyBytes = Math.ceil(clientKeyLength / 8);
        const clientRSACipher = (await legacyCrypto.generateKey({
            name: 'RSA-PKCS1-v1_5',
            modulusLength: clientKeyLength,
            publicExponent: new Uint8Array([1, 0, 1]),
        }, true, ['encrypt'])).privateKey;
        const clientExportedRSAKey = await legacyCrypto.exportKey('raw', clientRSACipher);
        this._checkConnected();
        const clientPublicKey = new Uint8Array(4 + clientKeyBytes * 2);
        clientPublicKey[0] = (clientKeyLength & 0xff000000) >>> 24;
        clientPublicKey[1] = (clientKeyLength & 0xff0000) >>> 16;
        clientPublicKey[2] = (clientKeyLength & 0xff00) >>> 8;
        clientPublicKey[3] = clientKeyLength & 0xff;
        clientPublicKey.set(clientExportedRSAKey.n, 4);
        clientPublicKey.set(clientExportedRSAKey.e, 4 + clientKeyBytes);
        this._sock.sQpushBytes(clientPublicKey);
        this._sock.flush();

        // 3: Exchange RSA-encrypted random values
        const clientRandom = new Uint8Array(this._randomBytes);
        window.crypto.getRandomValues(clientRandom);
        const clientEncryptedRandom = await legacyCrypto.encrypt(
            { name: 'RSA-PKCS1-v1_5' }, serverRSACipher, clientRandom);
        this._checkConnected();
        if (clientEncryptedRandom.length !== serverKeyBytes) {
            throw new Error("RA2: wrong encrypted message length");
        }
        const clientRandomMessage = new Uint8Array(2 + serverKeyBytes);
        clientRandomMessage[0] = (serverKeyBytes & 0xff00) >>> 8;
        clientRandomMessage[1] = serverKeyBytes & 0xff;
        clientRandomMessage.set(clientEncryptedRandom, 2);
        this._sock.sQpushBytes(clientRandomMessage);
        this._sock.flush();

        const serverRandom = await this._readEncryptedRandom(
            clientRSACipher, clientKeyBytes);
        let { clientCipher, serverCipher } = await this._deriveCiphers(
            clientRandom, serverRandom);
        this._clientCipher = clientCipher;
        this._serverCipher = serverCipher;
        this._checkConnected();

        // 4: Authenticate the key transcript
        const serverHash = await this._digest(serverPublicKey, clientPublicKey);
        const clientHash = await this._digest(clientPublicKey, serverPublicKey);
        this._checkConnected();
        const clientHashRecord = await clientCipher.seal(clientHash);
        this._checkConnected();
        this._sock.sQpushBytes(clientHashRecord);
        this._sock.flush();
        const serverHashReceived = await this._openRecord(
            serverCipher, this._hashBytes, 'server hash');
        for (let i = 0; i < this._hashBytes; i++) {
            if (serverHashReceived[i] !== serverHash[i]) {
                throw new Error("RA2: wrong server hash");
            }
        }

        // 5: Receive the credential subtype and send credentials
        const subtype = (await this._openRecord(serverCipher, 1, 'subtype'))[0];
        await this._waitForCredentials(subtype);
        this._checkConnected();
        const credentialsRecord = await clientCipher.seal(
            this._makeCredentials(subtype));
        this._checkConnected();
        this._sock.sQpushBytes(credentialsRecord);
        await this._sock.flush();

        if (this._rekey) {
            // 6: Exchange authenticated replacement randoms and derive fresh ciphers
            const replacementClientRandom = new Uint8Array(this._randomBytes);
            window.crypto.getRandomValues(replacementClientRandom);
            this._checkConnected();
            const replacementRandomRecord = await clientCipher.seal(
                replacementClientRandom);
            this._checkConnected();
            this._sock.sQpushBytes(replacementRandomRecord);
            await this._sock.flush();
            const replacementServerRandom = await this._openRecord(
                serverCipher, this._randomBytes, 'replacement random');
            this._discardCiphers();
            ({ clientCipher, serverCipher } = await this._deriveCiphers(
                replacementClientRandom, replacementServerRandom));
            this._clientCipher = clientCipher;
            this._serverCipher = serverCipher;
            this._checkConnected();
        }

        if (this._securityDetails.sessionEncrypted) {
            this._checkConnected();
            await this._sock.activateTransportTransform(clientCipher, serverCipher);
            this._clientCipher = null;
            this._serverCipher = null;
        } else {
            this._discardCiphers();
        }
    }

    async negotiateAuthAsync() {
        this._hasStarted = true;
        try {
            await this._negotiateAuthAsync();
        } catch (error) {
            this._discardCiphers();
            throw error;
        }
    }

    // Compatibility for callers from the original RA2ne-only implementation.
    negotiateRA2neAuthAsync() {
        return this.negotiateAuthAsync();
    }

    get securityDetails() {
        return this._securityDetails;
    }

    get hasStarted() {
        return this._hasStarted;
    }

    set hasStarted(s) {
        this._hasStarted = s;
    }
}
