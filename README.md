# sfcc_jwt
An implementation of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) for Salesforce Commerce Cloud SFRA.

# Install
Install the cartridge on server & add it to cartridge path.

# Usage

### jwt.sign(payload, options)

Returns the JsonWebToken as string.

`payload` is an object literal representing valid JSON.

`options`:

* `privateKeyOrSecret` is a string containing either the secret for HMAC algorithms or the private key for RSA.
* `algorithm` HS256, RS256 or similar
* `kid`

Sign with HMAC SHA256

```js
var jwt = require('plugin_jwt');
var options = {};
options.privateKeyOrSecret = 'my_secret';
options.algorithm = 'HS256';
var token = jwt.sign({ foo: 'bar' }, options);
```

Sign with RSA SHA256
```js
var privateKey = 'my_private_key';
var options = {};
options.privateKeyOrSecret = privateKey;
options.algorithm = 'RS256';
var token = jwt.sign({ foo: 'bar' }, options);
```

### jwt.verify(token, options)

Returns a boolean signifying if the signature is valid or not.

`token` is the JsonWebToken string

`algorithm` HS256, RS256 or similar

`options`:

* `publicKeyOrSecret` is a string containing either the secret for HMAC algorithms or the public key for RSA.

Verify HMAC SHA256

```js
var jwt = require('plugin_jwt');
var options = {};
options.publicKeyOrSecret = 'my_secret';
var isValid = jwt.verify(token, algorithm, options);
```

Verify RSA SHA256
```js
var publicKey = 'my_public_key';
var options = {};
options.publicKeyOrSecret = publicKey;
var isValid = jwt.verify(token, algorithm, options);
```

### jwt.decode(token, options)

Returns the decoded payload without verifying if the signature is valid.

`token` is the JsonWebToken string

```js
// get the decoded payload ignoring signature, no secretOrPrivateKey needed
var decoded = jwt.decode(token);
```

## Algorithms supported

Array of supported algorithms. The following algorithms are currently supported.

alg Parameter Value | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSA using SHA-256 hash algorithm
RS384 | RSA using SHA-384 hash algorithm
RS512 | RSA using SHA-512 hash algorithm


## Example

Check `JWTTest.js` controller for SFRA example.

## Note

This repository is heavily inspired from node-js repo [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
