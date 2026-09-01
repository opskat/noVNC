/* global module, process, require */

const base = require('../../karma.conf.cjs');

module.exports = (config) => {
    base({
        set(defaults) {
            const browserConfig = JSON.parse(process.env.RA2_LAB_BROWSER_CONFIG || '{}');
            config.set({
                ...defaults,
                basePath: '../..',
                files: [
                    { pattern: 'node_modules/chai/**', included: false },
                    { pattern: 'node_modules/sinon/**', included: false },
                    { pattern: 'node_modules/sinon-chai/**', included: false },
                    { pattern: 'core/**/*.js', included: false, type: 'module' },
                    { pattern: 'vendor/pako/**/*.js', included: false, type: 'module' },
                    { pattern: 'tests/integration/test.live.js', type: 'module' },
                    { pattern: 'tests/assertions.js', type: 'module' },
                ],
                client: {
                    args: [browserConfig],
                    mocha: {
                        reporter: 'html',
                        timeout: 30000,
                        ui: 'bdd',
                    },
                },
                browsers: ['ChromeHeadless'],
                browserDisconnectTimeout: 10000,
                browserNoActivityTimeout: 60000,
                captureTimeout: 120000,
                singleRun: true,
            });
        },
    });
};
