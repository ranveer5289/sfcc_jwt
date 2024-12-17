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

`options`:

* `publicKeyOrSecret` is a string containing either the secret for HMAC algorithms or the public key for RSA or a function which will return an appropriate [JSON Web Key Set](https://auth0.com/docs/tokens/concepts/jwks) for a kid. This function should return a modulus & exponential which then will be used to generate a DER format of public key. Note `PKCS#1` is not supported by SFCC, so you'd have to convert your pem to use `X.509/SPKI` format.
* `ignoreExpiration` is a boolean to skip JWT expiration time verification.
* `audience` is a string containing JWT audience.
* `issuer` is a string containing JWT issuer.

Verify HMAC SHA256

```js
var jwt = require('plugin_jwt');
var token = 'my_token';
var options = {};
options.publicKeyOrSecret = 'my_secret';
var isValid = jwt.verify(token, options);
```

Verify RSA SHA256
```js
var publicKey = 'my_public_key';
var token = 'my_token';
var options = {};
options.publicKeyOrSecret = publicKey;
var isValid = jwt.verify(token, options);
```

### jwt.decode(token, options)

Returns the decoded payload without verifying if the signature is valid.

`token` is the JsonWebToken string

```js
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
PS256 | RSA-PSS using SHA-256 hash algorithm
PS384 | RSA-PSS using SHA-384 hash algorithm


## Example

Check `JWTTest.js` controller for SFRA example.

## Resources

1. https://jwt.io/
2. https://jwt.io/introduction/
3. https://github.com/auth0/node-jsonwebtoken

## Note

This repository is heavily inspired from node-js repo [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
