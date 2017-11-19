'use strict';

const bcrypt = require('bcrypt');

module.exports = {
    createBcryptHash: (input, bcryptRounds) => {
        return new Promise((resolve, reject) => {
            bcrypt.genSalt(bcryptRounds, (err, salt) => {
                if(err) {
                    reject('Could not generate bcrypt salt. ' + err.toString());
                } else {
                    bcrypt.hash(input, salt, function(bcryptError, bcryptHash) {
                        if(bcryptError) {
                            reject('Coult not create a hash. ', bcryptError.toString());
                        } else {
                            resolve(bcryptHash);
                        }
                    });
                }
            });
        });
    }
};
