'use strict';

describe('createBcryptHash', () => {
    describe('on success', () => {
        const hasher = require('./hasher');
        const bcrypt = require('bcrypt');

        const fakeSalt = 'fake salt';
        const fakeHash = 'fake hash';
        const testInput = 'test input';
        const testNumRounds = 12;

        jest.mock('bcrypt', () => {
            return {
                genSalt: jest.fn(),
                hash: jest.fn()
            }
        });

        bcrypt.genSalt.mockImplementation((rounds, cb) => {
            cb(null, fakeSalt);
        });

        bcrypt.hash.mockImplementation((input, salt, cb) => {
            cb(null, fakeHash);
        });

        it('resolves with a hash', () => {
            return expect(hasher.createBcryptHash(testInput, testNumRounds)).resolves.toEqual(fakeHash);
        });

        it('calls bcrypt.genSalt with given rounds number', () => {
            hasher.createBcryptHash(testInput, testNumRounds);

            return expect(bcrypt.genSalt).toBeCalledWith(testNumRounds, expect.anything());
        });

        it('calls bcrypt.hash with given input and generated salt', () => {
            hasher.createBcryptHash(testInput, testNumRounds);

            return expect(bcrypt.hash).toBeCalledWith(testInput, fakeSalt, expect.anything());
        });
    });

    describe('rejects', () => {
        jest.resetModules();

        const hasher = require('./hasher');
        const bcrypt = require('bcrypt');

        jest.mock('bcrypt', () => {
            return {
                genSalt: jest.fn(),
                hash: jest.fn()
            }
        });

        describe('when genSalt()', () => {
            const genSaltError = 'gen-salt-error';

            bcrypt.genSalt = jest.fn().mockImplementationOnce((rounds, cb) => {
                cb(genSaltError);
            });

            it('reports an error', () => {
                return expect(hasher.createBcryptHash('aaa', 1)).rejects.toContain(genSaltError);
            });
        });

        describe('when hash()', () => {
            const hashError = 'bcrypt-hash-error';

            bcrypt.genSalt.mockImplementationOnce((rounds, cb) => {
                cb(null, 'fake-salt');
            });

            bcrypt.hash.mockImplementationOnce((input, salt, cb) => {
                cb(hashError);
            });

            it('reports an error', () => {
                return expect(hasher.createBcryptHash('aaa', 1)).rejects.toContain(hashError);
            });
        });
    });
});

describe('compareInputWithHash', () => {
    jest.resetModules();

    const hasher = require('./hasher');
    const bcrypt = require('bcrypt');

    jest.mock('bcrypt', () => {
        return {
            compare: jest.fn()
        }
    });

    it('rejects when hashes dont match', () => {
        bcrypt.compare.mockImplementationOnce((data, hash, cb) => {
            return Promise.reject('fail');
        });

        return expect(hasher.compareInputWithHash('input', 'hash')).rejects.toEqual('fail');
    });

    it('resolves when hashes match', () => {
        bcrypt.compare.mockImplementationOnce((data, hash, cb) => {
            return Promise.resolve(true);
        });

        return expect(hasher.compareInputWithHash('hash', 'hash')).resolves.toBeTruthy();
    });
});
