'use strict';


describe('scrambler', () => {
    const scrambler = require('./scrambler');
    const crypto = require('crypto');

    jest.mock('crypto', () => {
        return {
            createCipher: jest.fn(),
            createDecipher: jest.fn()
        }
    });

    describe('encrypt', () => {
        it('rejects when crypto throws', () => {
            crypto.createCipher.mockImplementationOnce((cipherType, password) => {throw new Error();})

            return expect(scrambler.encrypt('abc', 'password', 'aes111'))
                .rejects.toBeTruthy();
        });

        it('resolves with a string for correct params', () => {
            crypto.createCipher.mockImplementationOnce((cipherType, password) => {
                return {
                    update: () => 'abc',
                    final: () => 'def'
                }
            });

            return expect(scrambler.encrypt('abc', 'password', 'aes256'))
                .resolves.toEqual('abcdef');
        });
    });

    describe('decrypt', () => {
        jest.resetModules();

        it('rejects when crypto throws', () => {
            crypto.createDecipher.mockImplementationOnce((cipherType, password) => {throw new Error();})

            return expect(scrambler.decrypt('abc', 'password', 'aes111'))
                .rejects.toBeTruthy();
        });

        it('resolves with a string for correct params', () => {
            crypto.createDecipher.mockImplementationOnce((cipherType, password) => {
                return {
                    update: () => '123',
                    final: () => '456'
                }
            });

            return expect(scrambler.decrypt('abc', 'password', 'aes256'))
                .resolves.toEqual('123456');
        });
    });
});
