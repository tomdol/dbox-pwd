# Dropbox-like password hasher
Inspired by the way Dropbox crew stores their passwords https://blogs.dropbox.com/tech/2016/09/how-dropbox-securely-stores-your-passwords/

# API description
This library has a very simple API, only two functions, both documented in `index.js` file in the root directory.

`encrypt(input, password, bcryptRounds, cipherType)`

This function takes the `input` string and creates a bcrypt hash using `bcryptRounds` param value. The bigger the value, the longer it takes to calculate the hash(the salt to be more exact). This makes it secure and resistant to brute force attacks.

The calculated hash is then encrypted with selected cipher and a password. You can pass any of the supported node.js cipher type. The resulting value is returned via a promise. In case of any error - the promise rejects with an error message.

`compare(input, encryptedHash, password, cipherType)`

This function first decrypts the `encryptedHash`. Obviously the `password` and `cipherType` should match the pair used to encrypt the hash. When it's successfully decrypted, bcrypt compares the plain text `input` with the decrypted hash value. If those values match, the promise returned from `compare()` resolves with `true`, otherwise - `false`. The promise rejects if an error occurs in any of the described steps.

The Dropbox model assumes that each user's password has its own, cryptographically strong salt and that it's stored with the hash. The salt generation is provided by bcrypt itself. This means that wherever you store your users' data you just need to save one token that consists of the hash and salt in a single string. 

To make the storage more secure, a global pepper - `password` - is applied to encrypt all users' hashes. To lift the passwords storage to another level you can rotate the global pepper periodically and re-encrypt all passwords once in a while with a new one.
