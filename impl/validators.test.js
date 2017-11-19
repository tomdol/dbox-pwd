'use strict';

const validators = require('./validators');

const validInput = 'this is a valid input for the algorithm';
const validPassword = '7JP$,M:Kc68a*F@c';

describe('validateEncryptionParams:', () => {
    describe('input validation', () => {
        it('throws on empty input', () => {
            expect(() => validators.validateEncryptionParams('')).toThrow();
            expect(() => validators.validateEncryptionParams(null)).toThrow();
            expect(() => validators.validateEncryptionParams(undefined)).toThrow();
        });

        it('throws on non-string input', () => {
            expect(() => validators.validateEncryptionParams(123)).toThrow();
            expect(() => validators.validateEncryptionParams({})).toThrow();
            expect(() => validators.validateEncryptionParams([1,2,3])).toThrow();
        });
    });

    describe('password validation', () => {
        it('throws on empty password', () => {
            expect(() => validators.validateEncryptionParams(validInput, '')).toThrow();
            expect(() => validators.validateEncryptionParams(validInput, null)).toThrow();
            expect(() => validators.validateEncryptionParams(validInput, undefined)).toThrow();
        });

        it('throws on non-string password', () => {
            expect(() => validators.validateEncryptionParams(validInput, 123)).toThrow();
            expect(() => validators.validateEncryptionParams(validInput, {})).toThrow();
            expect(() => validators.validateEncryptionParams(validInput, [1,2,3])).toThrow();
        });
    });

    describe('cipher type validation', () => {
        it('throws on non-string cipherType', () => {
            expect(() =>
                validators.validateEncryptionParams(validInput, validPassword, 123)).toThrow();
            expect(() =>
                validators.validateEncryptionParams(validInput, validPassword, {})).toThrow();
            expect(() =>
                validators.validateEncryptionParams(validInput, validPassword, [1,2,3])).toThrow();
        });

        it('passes for aes128, aes256 and blowfish', () => {
            expect(() =>
                validators.validateEncryptionParams(validInput, validPassword, 'aes128')
            ).not.toThrow();

            expect(() =>
                validators.validateEncryptionParams(validInput, validPassword, 'aes256')
            ).not.toThrow();

            expect(() =>
                validators.validateEncryptionParams(validInput, validPassword, 'blowfish')
            ).not.toThrow();
        });
    });
});
