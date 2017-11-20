'use strict';

const crypto = require('crypto');

module.exports = {
    encrypt: (input, password, cipherType) => {
        const cipher = crypto.createCipher(cipherType, password);
        const enc1 = cipher.update(input, 'utf8', 'hex');
        const enc2 = cipher.final('hex');

        return enc1 + enc2;
    },

    decrypt: (data, password, cipherType) => {
        const decipher = crypto.createDecipher(cipherType, password);
        const dec1 = decipher.update(data, 'hex', 'utf8');
        const dec2 = decipher.final('utf8');

        return dec1 + dec2;
    }
};
