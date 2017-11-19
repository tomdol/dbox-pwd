'use strict'

const crypto = require('crypto');

module.exports = {
    validateEncryptionParams: (input, password, cipherType) => {
        if (typeof input !== 'string') {
            throw new Error('The input must be a string');
        }

        if (!input || input.length === 0) {
            throw new Error('The input data must not be empty');
        }

        if (typeof password !== 'string') {
            throw new Error('The password must be a string');
        }

        if (!password || password.length === 0) {
            throw new Error('The password must not be empty');
        }

        if (cipherType && typeof cipherType !== 'string') {
            throw new Error('cipherType must be a string');
        }

        const availableCiphers = crypto.getCiphers();
        if (availableCiphers.indexOf(cipherType) === -1) {
            throw new Error('The provided cipherType is not available in your version of node.js');
        }
    }
}
