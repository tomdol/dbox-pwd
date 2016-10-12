'use strict'

let bcrypt = require('bcrypt');
let crypto = require('crypto');

let DEFAULT_CIPHER = 'aes256';

module.exports = {
    /**
     * Encrypts the given input with bcrypt + selected cipher.
     * @param  {[string]} input        Data to encrypt. bcrypt expects input to be a string.
     * @param  {[string]} password     Password used to encrypt the hashed data. The same password should be used in compare function.
     * @param  {[number]} bcryptRounds Number of key expansion rounds in bcrypt. Bigger values provide better security of encrypted data but also take more time to compute the hash.
     * @param  {[string]} cipherType   One of cipher types available in nodejs's crypto module. By default aes256 is used. Call crypto.getCiphers() to check available ciphers.
     * @return {[Promise]}             Returns a Promise object. On success the resolve function is called with one param containing the encrypted input.
     */
    encrypt: function(input, password, bcryptRounds, cipherType) {
        return new Promise(function(resolve, reject) {
            try {
                if(typeof password !== 'string' || (cipherType && typeof cipherType !== 'string')) {
                    throw new Error('password and cipherType must be strings');
                }

                if(!input || input.length === 0) {
                    throw new Error('No input data');
                }

                let salt = bcrypt.genSaltSync(bcryptRounds);

                bcrypt.hash(input, salt, function(bcerror, hashedData) {
                    if(bcerror) {
                        throw bcerror;
                    } else {
                        let cipher = crypto.createCipher(cipherType || DEFAULT_CIPHER, password);
                        let enc1 = cipher.update(hashedData, 'utf8', 'hex');
                        let enc2 = cipher.final('hex');

                        resolve(enc1 + enc2);
                    }
                });
            } catch(err) {
                reject(err);
            }
        });
    },

    /**
     * The function decrypts encryptedData using the provided password. Decrypted data is then compared with input to see if the hashes match.
     * @param  {[string]} input         Input data to compare with decrypted hash.
     * @param  {[string]} encryptedData Hash encrypted with password and cipherType.
     * @param  {[string]} password      Password used to decrypt the encryptedData.
     * @param  {[string]} cipherType    Cipher used to decrypt the encryptedData. It needs to match the ciperType that was used to encrypt data.
     * @return {[Promise]}              Promise object which, on success, is resolved with a boolean value indicating that the input and encryptedData match(or not).
     */
    compare: function(input, encryptedData, password, cipherType) {
        return new Promise(function(resolve, reject) {
            try {
                if(typeof encryptedData !== 'string' || typeof password !== 'string' || (cipherType && typeof cipherType !== 'string')) {
                    throw new Error('encryptedData, password and cipherType must be strings');
                }

                if(!input || input.length === 0 || !encryptedData || encryptedData.length === 0) {
                    throw new Error('No input data');
                }

                let decipher = crypto.createDecipher(cipherType || DEFAULT_CIPHER, password);
                let dec1 = decipher.update(encryptedData, 'hex', 'utf8');
                let dec2 = decipher.final('utf8');

                let decrypted = dec1 + dec2;

                bcrypt.compare(input, decrypted, function(bcerror, result) {
                    if(bcerror) {
                        throw bcerror;
                    } else {
                        resolve(result);
                    }
                });

            } catch(err) {
                return null;
            }
        });
    }
};
