'use strict';

const validators = require('./impl/validators');
const hasher = require('./impl/hasher');
const scrambler = require('./impl/scrambler');

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
    encrypt: (input, password, bcryptRounds, cipherType = DEFAULT_CIPHER) => {
        return new Promise(function(resolve, reject) {
            try {
                // throws if validation fails, does nothing on success
                validators.validateEncryptionParams(input, password, cipherType);

                hasher.createBcryptHash(input, bcryptRounds)
                    .then(hash => {
                        const encryptedHash = scrambler.encrypt(hash, password, cipherType);

                        resolve(encryptedHash);
                    })
                    .catch(reject);
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
    compare: (input, encryptedData, password, cipherType) => {
        return new Promise(function(resolve, reject) {
            try {
                // throws if validation fails, does nothing on success
                validators.validateDecryptionParams(input, encryptedData, password, cipherType);

                const decryptedHash = scrambler.decrypt(encryptedData, password, cipherType || DEFAULT_CIPHER);

                return hasher.compareInputWithHash(input, decryptedHash);
            } catch(err) {
                reject(error);
            }
        });
    }
};
