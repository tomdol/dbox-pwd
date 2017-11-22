'use strict';

describe('Public API test:', () => {
    jest.mock('./hasher');
    jest.mock('./validators');
    jest.mock('./scrambler');

    const hasher = require('./hasher');
    const scrambler = require('./scrambler');
    const validators = require('./validators');
    const dboxpwd = require('../index');

    const testInput = 'some input';
    const encryptedHash = 'some encrypted data';
    const testPassword = 'sag34,.,23r';
    const testErr = 'some error';

    describe('encrypt()', () => {
        validators.validateEncryptionParams.mockImplementation(() => Promise.resolve());
        hasher.createBcryptHash.mockImplementation((input, bcryptRounds) => input);
        scrambler.encrypt.mockImplementation((input, password, cipherType) => input);

        it('resolves with a string for correct params', () => {
            return expect(dboxpwd.encrypt(testInput, testPassword, 10)).resolves.toEqual(testInput);
        });

        it('rejects when validator rejects', () => {
            validators.validateEncryptionParams.mockImplementationOnce(() => Promise.reject(testErr));

            return expect(dboxpwd.encrypt(testInput, null, 5)).rejects.toEqual(testErr);
        });

        it('rejects when bcrypt hash fails', () => {
             hasher.createBcryptHash.mockImplementationOnce(() => Promise.reject(testErr));

             return expect(dboxpwd.encrypt(testInput, testPassword, 0)).rejects.toEqual(testErr);
        });

        it('rejects when encryption fails', () => {
            scrambler.encrypt.mockImplementationOnce(() => Promise.reject(testErr));

            return expect(dboxpwd.encrypt(testInput, testPassword, 7, 'unknown')).rejects.toEqual(testErr);
        });
    });

    describe('compare()', () => {
        validators.validateDecryptionParams.mockImplementation(() => Promise.resolve());
        scrambler.decrypt.mockImplementation((data, password, cipherType) => data);
        hasher.compareInputWithHash.mockImplementation((input, hash) => Promise.resolve(true));

        it('resolves with true when input matches hash', () => {
            return expect(dboxpwd.compare(testInput, encryptedHash, testPassword, 10)).resolves.toBeTruthy();
        });

        it('resolves with false when hashes dont match', () => {
            hasher.compareInputWithHash.mockImplementationOnce(() => Promise.resolve(false));

            return expect(dboxpwd.compare('wrong password', encryptedHash, 5)).resolves.toBeFalsy();
        });

        it('rejects when validator rejects', () => {
            validators.validateDecryptionParams.mockImplementationOnce(() => Promise.reject(testErr));

            return expect(dboxpwd.compare('', encryptedHash, null, 'aes123')).rejects.toEqual(testErr);
        });

        it('rejects when decryption fails', () => {
            scrambler.decrypt.mockImplementationOnce(() => Promise.reject(testErr));

            return expect(dboxpwd.compare(testInput, encryptedHash, testPassword, 'unknown')).rejects.toEqual(testErr);
        });
    });
});
