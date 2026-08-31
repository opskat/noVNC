#!/usr/bin/env node
/* global process */
/* eslint-disable no-console */

import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { listenWebSocketProxy } = require('./websocket_proxy.cjs');

const endpointHost = process.env.RA2_LAB_HOST;
const password = process.env.RA2_LAB_PASSWORD;
const reportPath = process.env.RA2_LAB_REPORT;
const proxyBasePort = Number(process.env.RA2_LAB_PROXY_BASE_PORT || 16911);

if (!endpointHost) {
    console.error('RA2_LAB_HOST is required');
    process.exit(2);
}
if (!password) {
    console.error('RA2_LAB_PASSWORD is required');
    process.exit(2);
}

const endpoints = [
    { port: 5911, name: 'RA2', type: 5, sessionEncrypted: true, aesBits: 128 },
    { port: 5912, name: 'RA2ne', type: 6, sessionEncrypted: false, aesBits: 128 },
    { port: 5913, name: 'RA2_256', type: 129, sessionEncrypted: true, aesBits: 256 },
    { port: 5914, name: 'RA2ne_256', type: 130, sessionEncrypted: false, aesBits: 256 },
    { port: 5915, name: 'VNCAuth', type: 2, sessionEncrypted: false },
    { port: 5916, name: 'RA2r', type: 13, sessionEncrypted: true, aesBits: 128 },
    { port: 5917, name: 'RA2r_256', type: 133, sessionEncrypted: true, aesBits: 256 },
].map((endpoint, index) => ({
    ...endpoint,
    websocketUrl: `ws://127.0.0.1:${proxyBasePort + index}`,
}));

const proxies = [];
try {
    for (const [index, endpoint] of endpoints.entries()) {
        proxies.push(await listenWebSocketProxy({
            listenPort: proxyBasePort + index,
            targetHost: endpointHost,
            targetPort: endpoint.port,
        }));
    }

    const child = spawn(process.execPath, [
        './node_modules/karma/bin/karma',
        'start',
        'tests/integration/karma.conf.cjs',
    ], {
        stdio: ['inherit', 'pipe', 'pipe'],
        env: {
            ...process.env,
            RA2_LAB_BROWSER_CONFIG: JSON.stringify({ endpoints, password }),
        },
    });
    let karmaOutput = '';
    child.stdout.on('data', (data) => {
        karmaOutput += data;
        process.stdout.write(data);
    });
    child.stderr.on('data', (data) => {
        karmaOutput += data;
        process.stderr.write(data);
    });

    let exitCode = await new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', (code, signal) => {
            if (signal) {
                reject(new Error(`Karma terminated by ${signal}`));
            } else {
                resolve(code ?? 1);
            }
        });
    });

    const policyMatrix = [];
    for (const match of karmaOutput.matchAll(/RA2_LAB_RESULT (\{.*\})/g)) {
        policyMatrix.push(JSON.parse(match[1]));
    }
    if (exitCode === 0 && policyMatrix.length !== 35) {
        console.error(`Expected 35 policy results, received ${policyMatrix.length}`);
        exitCode = 1;
    }
    const report = {
        generatedAt: new Date().toISOString(),
        endpointHost,
        endpoints: endpoints.map(({ websocketUrl, ...endpoint }) => endpoint),
        policyMatrix,
        exitCode,
    };
    if (reportPath) {
        await mkdir(path.dirname(reportPath), { recursive: true });
        await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
    }
    process.exitCode = exitCode;
} finally {
    await Promise.all(proxies.map(proxy => new Promise(resolve => proxy.close(resolve))));
}
