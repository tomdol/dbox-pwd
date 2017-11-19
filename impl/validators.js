'use strict'

const crypto = require('crypto');

const isNonEmptyString = (value, paramName) => {
    if (typeof value !== 'string') {
        throw new Error(`The ${paramName} must be a string`);
    }

    if (!value || value.length === 0) {
        throw new Error(`The ${paramName} must not be empty`);
    }
};

module.exports = {
    validateEncryptionParams: (input, password, cipherType) => {
        isNonEmptyString(input, 'input data');
        isNonEmptyString(password, 'password');
        isNonEmptyString(cipherType, 'cipher type');

        if (crypto.getCiphers().indexOf(cipherType) === -1) {
            throw new Error('The provided cipherType is not available in your version of node.js');
        }
    },

    validateDecryptionParams: (input, encryptedData, password, cipherType) => {
        module.exports.validateEncryptionParams(input, password, cipherType);

        isNonEmptyString(encryptedData, 'encrypted data');
    }
}
