var jwtHelper = require('*/cartridge/scripts/jwt/jwtHelper');
var jwtDecode = require('*/cartridge/scripts/jwt/decode');

var Logger = require('dw/system/Logger');
var Bytes = require('dw/util/Bytes');
var Encoding = require('dw/crypto/Encoding');
var Signature = require('dw/crypto/Signature');
var StringUtils = require('dw/util/StringUtils');

var JWTAlgoToVerifierMapping = {
    "RS256" : createRSAVerifier
};

var JWTAlgoToSFCCMapping = jwtHelper.JWTAlgoToSFCCMapping;

function verifyJWT(jwt, algorithm, options) {
    var options = options || {};

    if (!jwtHelper.isValidJWT(jwt)) {
        return false;
    }
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
    }

    if (!publicKeyOrSecret) {
        throw new Error('Cannot verify JWT token as public key or secret not supplied');
    }

    var verifier = JWTAlgoToVerifierMapping[algorithm];
    if (!verifier) {
        throw new Error(StringUtils.format('No verifier function found for supplied algorithm {0}', algorithm));
    }

    var verified = verifier(jwtSig, contentToVerify, publicKeyOrSecret, algorithm);
    return verified;
}

function createRSAVerifier(signature, input, publicKey, algorithm) {
    var jwtSignatureInBytes = new Encoding.fromBase64(signature);
    var contentToVerifyInBytes = new Bytes(input);

    var apiSig = new Signature();
    var verified = apiSig.verifyBytesSignature(jwtSignatureInBytes, contentToVerifyInBytes, new Bytes(publicKey), JWTAlgoToSFCCMapping[algorithm]);
    return verified

}
module.exports.verifyJWT = verifyJWT;
