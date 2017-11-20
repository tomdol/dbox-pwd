'use strict';

const bcrypt = require('bcrypt');

module.exports = {
    createBcryptHash: (input, bcryptRounds) => {
        return new Promise((resolve, reject) => {
            bcrypt.genSalt(bcryptRounds, (saltGenError, salt) => {
                if(saltGenError) {
                    reject('Could not generate bcrypt salt. ' + saltGenError.toString());
                } else {
                    bcrypt.hash(input, salt, function(hashError, bcryptHash) {
                        if(hashError) {
                            reject('Coult not create a hash. ' + hashError.toString());
                        } else {
                            resolve(bcryptHash);
                        }
                    });
                }
            });
        });
    },

    compareInputWithHash: (input, hash) => {
        return bcrypt.compare(input, hash, null);
    }
};
