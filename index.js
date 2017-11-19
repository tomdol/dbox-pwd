'use strict'

const bcrypt = require('bcrypt');
const crypto = require('crypto');

const DEFAULT_CIPHER = 'aes256';

module.exports = {
    /**
     * Hashes and encrypts the given input with bcrypt + selected cipher.

     * @param  {[string]} input        Data to hash & encrypt. bcrypt expects input to be a string.
     * @param  {[string]} password     Password used to encrypt the hashed data. The same password should be used in compare function for verification.
     * @param  {[number]} bcryptRounds Number of key expansion rounds in bcrypt. Bigger values provide better security of encrypted data but also take more time to compute the hash.
     * @param  {[string]} cipherType   One of cipher types available in nodejs's crypto module. By default aes256 is used. Call crypto.getCiphers() to check available ciphers.
     * @return {[Promise]}             On success the returned promise resolves with the hashed and encrypted input.
     */
    encrypt: (input, password, bcryptRounds, cipherType) => {
        return new Promise(function(resolve, reject) {
            try {
                if(typeof password !== 'string' || (cipherType && typeof cipherType !== 'string')) {
                    throw new Error('Both password and cipherType must be strings');
                }

                if(!input || input.length === 0) {
                    throw new Error('The input data cannot be empty');
                }

                bcrypt.genSalt(bcryptRounds, (err, salt) => {
                    if(err) {
                        throw new Error('Could not generate bcrypt salt. ' + saltGenerationError.toString());
                    } else {
                        bcrypt.hash(input, salt, function(bcerror, hashedData) {
                            if(bcerror) {
                                throw bcerror;
                            } else {
                                const cipher = crypto.createCipher(cipherType || DEFAULT_CIPHER, password);
                                const enc1 = cipher.update(hashedData, 'utf8', 'hex');
                                const enc2 = cipher.final('hex');

                                resolve(enc1 + enc2);
                            }
                        });
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

                const decipher = crypto.createDecipher(cipherType || DEFAULT_CIPHER, password);
                const dec1 = decipher.update(encryptedData, 'hex', 'utf8');
                const dec2 = decipher.final('utf8');

                const decrypted = dec1 + dec2;

                bcrypt.compare(input, decrypted, function(bcryptError, result) {
                    if(bcryptError) {
                        throw bcryptError;
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
