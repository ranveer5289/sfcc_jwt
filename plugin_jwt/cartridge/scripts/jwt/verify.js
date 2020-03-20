var jwtHelper = require('*/cartridge/scripts/jwt/jwtHelper');
var jwtDecode = require('*/cartridge/scripts/jwt/decode');

var Logger = require('dw/system/Logger');
var Bytes = require('dw/util/Bytes');
var Encoding = require('dw/crypto/Encoding');
var Signature = require('dw/crypto/Signature');
var StringUtils = require('dw/util/StringUtils');
var Mac = require('dw/crypto/Mac');

var JWTAlgoToVerifierMapping = {
    "RS256" : createRSAVerifier,
    "RS384" : createRSAVerifier,
    "RS512" : createRSAVerifier,
    "HS256": createHMACVerifier,
    "HS384": createHMACVerifier,
    "HS512": createHMACVerifier,
    "PS256": createRSAVerifier,
    "PS384": createRSAVerifier
};

var JWTAlgoToSFCCMapping = jwtHelper.JWTAlgoToSFCCMapping;

function verifyJWT(jwt, options) {
    var options = options || {};

    
    if (!jwtHelper.isValidJWT(jwt)) {
        return false;
    }
    
    var decodedToken = jwtDecode.decodeJWT(jwt);
    if (!decodedToken) {
        return false;
    }
    
    var algorithm = decodedToken.header.alg;
    var parts = jwt.split('.');

    var supportedAlgorithms = jwtHelper.SUPPORTED_ALGORITHMS;
    if (supportedAlgorithms.indexOf(algorithm) === -1) {
        throw new Error(StringUtils.format('JWT Algorithm {0} not supported', algorithm));
    }

    var header = parts[0];
    var payload = parts[1];
    var jwtSig = parts[2];

    var contentToVerify = header + '.' + payload;

    var publicKeyOrSecret;
    if(options.publicKeyOrSecret && typeof options.publicKeyOrSecret === 'string') {
        publicKeyOrSecret = options.publicKeyOrSecret;
    } else if(options.publicKeyOrSecret && typeof options.publicKeyOrSecret === 'function') {
        var jsonWebKey = options.publicKeyOrSecret(decodedToken);
        if (jsonWebKey && jsonWebKey.modulus && jsonWebKey.exponential) {
            var keyHelper = require('*/cartridge/scripts/helpers/rsaToDer');
            publicKeyOrSecret = keyHelper.getRSAPublicKey(jsonWebKey.modulus, jsonWebKey.exponential);
        }
    }

    if (!publicKeyOrSecret) {
        throw new Error('Cannot verify JWT token as public key or secret not supplied');
    }

    var verifier = JWTAlgoToVerifierMapping[algorithm];
    if (!verifier) {
        throw new Error(StringUtils.format('No verifier function found for supplied algorithm {0}', algorithm));
    }

    var verified = verifier(jwtSig, contentToVerify, publicKeyOrSecret, algorithm);
    if (!verified) {
        return false;
    }

    var payload = decodedToken.payload;
    if (!options.ignoreExpiration) {
        var jwtExp = payload.exp;
        //seconds to ms
        var expirationDate = new Date(jwtExp * 1000);
        var currentDate = new Date();
        // expired
        if (expirationDate < currentDate) {
            return false;
        }
    }

    if (options.audience) {
        var aud = payload.aud;
        if (options.audience !== aud) {
            return false;
        }
    }

    if (options.issuer) {
        var iss = payload.iss;
        if (iss !== options.issuer) {
            return false;
        }
    }

    return true;
}

function createRSAVerifier(signature, input, publicKey, algorithm) {
    var jwtSignatureInBytes = new Encoding.fromBase64(signature);
    var contentToVerifyInBytes = new Bytes(input);

    var apiSig = new Signature();
    var verified = apiSig.verifyBytesSignature(jwtSignatureInBytes, contentToVerifyInBytes, new Bytes(publicKey), JWTAlgoToSFCCMapping[algorithm]);
    return verified
}

function createHMACVerifier(signature, input, secret, algorithm) {
    var mac = new Mac(JWTAlgoToSFCCMapping[algorithm]);
    var inputInBytes = new Bytes(input);
    var secretInBytes = new Bytes(secret);

    // create digest of input & compare against jwt signature
    var outputInBytes = mac.digest(inputInBytes, secretInBytes);
    var outputInString = Encoding.toBase64(outputInBytes); 

    // signature is base64UrlEncoded so convert input to same
    var urlEncodedOutput = jwtHelper.toBase64UrlEncoded(outputInString);

    return signature === urlEncodedOutput;
}
module.exports.verifyJWT = verifyJWT;
