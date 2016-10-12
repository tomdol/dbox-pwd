'use strict'

var dboxpwd = require('./index');

//this should be stored somewhere else than users and their passwords
//it could be a file with permissions: "-r--------" which should be read every time the 'secret' is required to encrypt/decrypt data
let secret = 'secretPassword123';

let registerUser = function() {
    //data from the registration form
    let userName = 'tomek';
    let userPassword = 'password123';

    //Hash and encrypt the password. Choose the bcryptRounds value experimentally. Bigger values are more secure but also more time consuming.
    //The value can be stored in a config file and increased periodically(for example +1 every year).
    dboxpwd.encrypt(userPassword, secret, 10)
    .then(function(encryptedPassword) {
        console.log('Encrypted password:', encryptedPassword);
        //now you can save user information to db
        //db.saveUser(userName, encryptedPassword)
    })
    .catch(function(error) {
        console.error(error);
    });
};

let successfulLogin = function() {
    //data from the login form
    let userName = 'tomek';
    let userPassword = 'password123';

    //select the user information from db
    let userPasswordFromDB = '591e81c3c3491709095f13d296fe013f57c5ebc98a2371decae2b0555e6030e96a6ddb4bcaba78d51097262b7728e56f01c2c53380f06f5e9ac5edca0125eb1b';

    dboxpwd.compare(userPassword, userPasswordFromDB, secret)
    .then(function(passwordsMatch) {
        if(passwordsMatch) {
            console.log('Login successful');
            //create session, etc...
        } else {
            console.error('Wrong user name or password');
            //
        }
    })
    .catch(function(error) {
        //something went wrong during password decryption or comparison
        console.error(error);
    });
};

let unsuccessfulLogin = function() {
    //data from the login form
    let userName = 'tomek';
    let userPassword = 'incorrectPassword';

    //select the user information from db
    let userPasswordFromDB = '591e81c3c3491709095f13d296fe013f57c5ebc98a2371decae2b0555e6030e96a6ddb4bcaba78d51097262b7728e56f01c2c53380f06f5e9ac5edca0125eb1b';

    dboxpwd.compare(userPassword, userPasswordFromDB, secret)
    .then(function(passwordsMatch) {
        if(passwordsMatch) {
            console.log('Login successful');
            //create session, etc...
        } else {
            console.error('Wrong user name or password');
            //
        }
    })
    .catch(function(error) {
        //something went wrong during password decryption or comparison
        console.error(error);
    });
};

//to test run: node example.js
registerUser();

successfulLogin();

unsuccessfulLogin();
