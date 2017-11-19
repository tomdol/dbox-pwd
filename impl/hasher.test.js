'use strict';

describe('createBcryptHash', () => {
    jest.mock('bcrypt', () => {
        return {
            genSalt: (bcryptRounds, cb) => {
                cb(null, {});
            },
            hash: (data, salt, cb) => {
                cb(null, {});
            }
        }
    });

    const hasher = require('./hasher');
    const bcrypt = require('bcrypt');

    const testInput = 'test input';
    const testNumRounds = 12;

    it('resolves as an empty object', () => {
        expect.hasAssertions();

        return expect(hasher.createBcryptHash('aaa', 1)).resolves.toEqual({});
    });

    it('calls bcrypt.genSalt with given rounds number', () => {
        const mockedGenSalt = jest.spyOn(bcrypt, 'genSalt');

        hasher.createBcryptHash(testInput, testNumRounds);

        return expect(mockedGenSalt).toBeCalledWith(testNumRounds, expect.anything());
    });

    it('calls bcrypt.hash with given input', () => {
        const mockedHash = jest.spyOn(bcrypt, 'hash');

        hasher.createBcryptHash(testInput, testNumRounds);

        return expect(mockedHash).toBeCalledWith(testInput, expect.anything(), expect.anything());
    });
});
