/* global describe, expect, it */
/* eslint-disable no-console */

import RFB from '../../core/rfb.js';

const config = window.__karma__.config.args[0];

const POLICIES = [
    { name: 'server', groups: null, allowed: [2, 5, 6, 13, 129, 130, 133] },
    { name: 'always_maximum', groups: [[133, 129]], allowed: [129, 133] },
    { name: 'always_on', groups: [[133, 129, 13, 5]], allowed: [5, 13, 129, 133] },
    { name: 'prefer_on', groups: [[133, 129, 13, 5], [6, 130, 2]], allowed: [2, 5, 6, 13, 129, 130, 133] },
    { name: 'prefer_off', groups: [[6, 130, 2], [133, 129, 13, 5]], allowed: [2, 5, 6, 13, 129, 130, 133] },
];

function waitForEvent(target, name, timeout = 15000) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            target.removeEventListener(name, listener);
            reject(new Error(`Timed out waiting for ${name}`));
        }, timeout);
        const listener = (event) => {
            clearTimeout(timer);
            resolve(event);
        };
        target.addEventListener(name, listener, { once: true });
    });
}

async function waitForFramebuffer(rfb, timeout = 10000) {
    const deadline = performance.now() + timeout;
    while (performance.now() < deadline) {
        const image = rfb.getImageData();
        if (image.width > 0 && image.height > 0 && image.data.some(value => value !== 0)) {
            return { width: image.width, height: image.height };
        }
        await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error('Timed out waiting for a non-empty framebuffer update');
}

function makeClient(endpoint, policy) {
    const target = document.createElement('div');
    const authenticationEvents = [];
    target.style.width = '640px';
    target.style.height = '480px';
    document.body.appendChild(target);
    const options = {
        credentials: { password: config.password },
        shared: true,
    };
    if (policy.groups !== null) {
        options.securityPolicy = policy.groups;
    }
    const rfb = new RFB(target, endpoint.websocketUrl, options);
    rfb.addEventListener('serververification', () => {
        authenticationEvents.push('serververification');
        rfb.approveServer();
    });
    rfb.addEventListener('credentialsrequired', () => {
        authenticationEvents.push('credentialsrequired');
        rfb.sendCredentials({ username: '', password: config.password });
    });
    return { rfb, target, authenticationEvents };
}

async function disconnect(rfb) {
    const disconnected = waitForEvent(rfb, 'disconnect', 5000);
    rfb.disconnect();
    await disconnected;
}

async function exerciseFlow(rfb, target, endpoint, policy) {
    const framebuffer = await waitForFramebuffer(rfb);
    // Force deterministic legacy wire messages while still exercising the public
    // noVNC input and clipboard methods. Some TigerVNC capabilities otherwise
    // replace these markers with negotiated extension messages.
    rfb._qemuExtKeyEventSupported = false;
    rfb._clipboardServerCapabilitiesFormats = {};
    rfb._clipboardServerCapabilitiesActions = {};
    rfb.sendKey(0x78, 'KeyX', true);
    rfb.sendKey(0x78, 'KeyX', false);

    const canvas = target.querySelector('canvas');
    expect(canvas, 'noVNC canvas').to.not.equal(null);
    canvas.dispatchEvent(new MouseEvent('mousemove', {
        bubbles: true,
        clientX: 7,
        clientY: 1,
    }));
    canvas.dispatchEvent(new MouseEvent('mousedown', {
        bubbles: true,
        button: 0,
        buttons: 1,
        clientX: 7,
        clientY: 1,
    }));
    canvas.dispatchEvent(new MouseEvent('mouseup', {
        bubbles: true,
        button: 0,
        buttons: 0,
        clientX: 7,
        clientY: 1,
    }));

    const clipboardMarker = `OPSKAT_CLIENT_CLIPBOARD_${endpoint.port}_${policy.name}`;
    rfb.clipboardPasteFrom(clipboardMarker);
    await new Promise(resolve => setTimeout(resolve, 300));
    return { framebuffer, clipboardMarker };
}

describe('live RSA-AES interoperability lab', function liveLab() {
    this.timeout(30000);

    for (const policy of POLICIES) {
        for (const endpoint of config.endpoints) {
            const expectedSuccess = policy.allowed.includes(endpoint.type);
            it(`${policy.name} ${expectedSuccess ? 'accepts' : 'rejects'} ${endpoint.name}`, async () => {
                const { rfb, target, authenticationEvents } = makeClient(endpoint, policy);
                const events = [];
                let negotiated = null;
                let connectionFailure = null;
                rfb.addEventListener('negotiatedsecurity', (event) => {
                    events.push('negotiatedsecurity');
                    negotiated = event.detail;
                });
                rfb.addEventListener('connect', () => events.push('connect'));
                rfb.addEventListener('connectionfailure', (event) => {
                    events.push('connectionfailure');
                    connectionFailure = event.detail;
                });
                rfb.addEventListener('disconnect', () => events.push('disconnect'));

                if (!expectedSuccess) {
                    const disconnected = await waitForEvent(rfb, 'disconnect');
                    expect(events).to.deep.equal(['connectionfailure', 'disconnect']);
                    expect(disconnected.detail.clean).to.be.false;
                    expect(connectionFailure).to.deep.equal({
                        code: 'policy-rejected',
                        message: 'The server does not offer a security type allowed by the configured policy.',
                        offeredTypes: [endpoint.type],
                    });
                    expect(authenticationEvents, 'authentication must not start').to.deep.equal([]);
                    console.log('RA2_LAB_RESULT ' + JSON.stringify({
                        policy: policy.name,
                        endpoint: endpoint.name,
                        port: endpoint.port,
                        expected: 'rejection',
                        observed: 'rejection',
                        connectionFailure,
                    }));
                    target.remove();
                    return;
                }

                await waitForEvent(rfb, 'connect');
                expect(events).to.deep.equal(['negotiatedsecurity', 'connect']);
                expect(connectionFailure).to.equal(null);
                expect(negotiated).to.deep.equal({
                    type: endpoint.type,
                    name: endpoint.name,
                    authenticationEncrypted: endpoint.type !== 2,
                    sessionEncrypted: endpoint.sessionEncrypted,
                    ...(endpoint.aesBits === undefined ? {} : { aesBits: endpoint.aesBits }),
                });
                const flow = await exerciseFlow(rfb, target, endpoint, policy);
                console.log('RA2_LAB_RESULT ' + JSON.stringify({
                    policy: policy.name,
                    endpoint: endpoint.name,
                    port: endpoint.port,
                    expected: 'success',
                    observed: 'success',
                    negotiated,
                    framebuffer: flow.framebuffer,
                    keyboard: true,
                    pointer: true,
                    clipboardMarker: flow.clipboardMarker,
                }));
                await disconnect(rfb);
                expect(events).to.deep.equal([
                    'negotiatedsecurity', 'connect', 'disconnect',
                ]);
                expect(connectionFailure).to.equal(null);
                target.remove();
            });
        }
    }
});
