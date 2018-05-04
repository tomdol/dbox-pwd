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
    const testHash = 'some fake hash';
    const encryptedHash = 'some encrypted hash';
    const testPassword = 'some test password';
    const testErr = 'some error';

    describe('encrypt()', () => {
        validators.validateEncryptionParams.mockReturnValue(Promise.resolve());
        hasher.createBcryptHash.mockReturnValue(Promise.resolve(testHash));
        scrambler.encrypt.mockReturnValue(Promise.resolve(encryptedHash));

        beforeEach(() => {
            validators.validateEncryptionParams.mockClear();
            hasher.createBcryptHash.mockClear();
            scrambler.encrypt.mockClear();
        });

        it('resolves with a string for correct params', () => {
            return expect(dboxpwd.encrypt(testInput, testPassword, 10)).resolves.toEqual(encryptedHash);
        });

        it('rejects when validator rejects', () => {
            validators.validateEncryptionParams.mockReturnValueOnce(Promise.reject(testErr));

            return expect(dboxpwd.encrypt(testInput, null, 5)).rejects.toEqual(testErr);
        });

        it('rejects when bcrypt hash fails', () => {
            hasher.createBcryptHash.mockReturnValueOnce(Promise.reject(testErr));

            return expect(dboxpwd.encrypt(testInput, testPassword, 0)).rejects.toEqual(testErr);
        });

        it('rejects when encryption fails', () => {
            scrambler.encrypt.mockReturnValueOnce(Promise.reject(testErr));

            return expect(dboxpwd.encrypt(testInput, testPassword, 7, 'unknown')).rejects.toEqual(testErr);
        });

        it('calls create hash with input and bcrypt rounds', () => {
            return dboxpwd.encrypt(testInput, testPassword, 120).then(data => {
                expect(hasher.createBcryptHash).toBeCalledWith(testInput, 120)
            });
        });

        it('passes the generated hash and password to encryption function', () => {
            return dboxpwd.encrypt(testInput, testPassword, 10).then(data => {
                expect(scrambler.encrypt).toBeCalledWith(testHash, testPassword, expect.anything());
            });
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
