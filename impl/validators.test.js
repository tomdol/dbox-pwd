'use strict';

const validators = require('./validators');

const validInput = 'this is a valid input for the algorithm';
const validPassword = '7JP$,M:Kc68a*F@c';

describe('validateEncryptionParams:', () => {
    describe('input validation', () => {
        it('rejects on empty input', () => {
            expect.hasAssertions();

            expect(validators.validateEncryptionParams('')).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams(null)).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams(undefined)).rejects.toBeTruthy();
        });

        it('rejects on non-string input', () => {
            expect.hasAssertions();

            expect(validators.validateEncryptionParams(123)).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams({})).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams([1,2,3])).rejects.toBeTruthy();
        });
    });

    describe('password validation', () => {
        it('rejects on empty password', () => {
            expect.hasAssertions();

            expect(validators.validateEncryptionParams(validInput, '')).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams(validInput, null)).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams(validInput, undefined)).rejects.toBeTruthy();
        });

        it('rejects on non-string password', () => {
            expect(validators.validateEncryptionParams(validInput, 123)).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams(validInput, {})).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams(validInput, [1,2,3])).rejects.toBeTruthy();
        });
    });

    describe('cipher type validation', () => {
        it('rejects on non-string cipherType', () => {
            expect(validators.validateEncryptionParams(validInput, validPassword, 123)).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams(validInput, validPassword, {})).rejects.toBeTruthy();
            expect(validators.validateEncryptionParams(validInput, validPassword, [1,2,3])).rejects.toBeTruthy();
        });

        it('resolves as undefined for aes128, aes256 and blowfish', () => {
            expect(validators.validateEncryptionParams(validInput, validPassword, 'aes128')).resolves.toBe(undefined);
            expect(validators.validateEncryptionParams(validInput, validPassword, 'aes256')).resolves.toBe(undefined);
            expect(validators.validateEncryptionParams(validInput, validPassword, 'blowfish')).resolves.toBe(undefined);
        });
    });
});

describe('validateDecryptionParams:', () => {
    it('throws on empty input', () => {
        expect(validators.validateDecryptionParams(validInput, '', validPassword, 'aes256')).rejects.toBeTruthy();
        expect(validators.validateDecryptionParams(validInput, null, validPassword, 'aes256')).rejects.toBeTruthy();
        expect(validators.validateDecryptionParams(validInput, undefined, validPassword, 'aes256'))
            .rejects.toBeTruthy();
    });

    it('throws on non-string input', () => {
        expect(validators.validateDecryptionParams(validInput, 123, validPassword, 'aes256')).rejects.toBeTruthy();
    });

    it('resolves as undefined for accepted values', () => {
        expect(validators.validateDecryptionParams(validInput, 'some string', validPassword, 'aes256'))
            .resolves.toBe(undefined);
    });
});
