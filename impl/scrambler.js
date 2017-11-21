'use strict';

const crypto = require('crypto');

const encrypt = (input, password, cipherType) => {
    const cipher = crypto.createCipher(cipherType, password);
    const enc1 = cipher.update(input, 'utf8', 'hex');
    const enc2 = cipher.final('hex');

    return enc1 + enc2;
};

const decrypt = (data, password, cipherType) => {
    const decipher = crypto.createDecipher(cipherType, password);
    const dec1 = decipher.update(data, 'hex', 'utf8');
    const dec2 = decipher.final('utf8');

    return dec1 + dec2;
};

module.exports = {
    encrypt: (input, password, cipherType) => {
        try {
            return Promise.resolve(encrypt(input, password, cipherType));
        } catch(err) {
            return Promise.reject(err);
        }
    },

    decrypt: (data, password, cipherType) => {
        try {
            return Promise.resolve(decrypt(data, password, cipherType));
        } catch(err) {
            return Promise.reject(err);
        }
    }
};
