var jwtHelper = require('*/cartridge/scripts/jwt/jwtHelper');
var Logger = require('dw/system/Logger');
var Encoding = require('dw/crypto/Encoding');
var Bytes = require('dw/util/Bytes');
var Signature = require('dw/crypto/Signature');
var StringUtils = require('dw/util/StringUtils');
var Mac = require('dw/crypto/Mac');

var JWTAlgoToSignMapping = {
    "RS256" : signWithRSA,
    "RS384" : signWithRSA,
    "RS512" : signWithRSA,
    "HS256": signWithHMAC,
    "HS384": signWithHMAC,
    "HS512": signWithHMAC,
    "PS256": signWithRSA,
    "PS384": signWithRSA
};


var JWTAlgoToSFCCMapping = jwtHelper.JWTAlgoToSFCCMapping;

function signJWT(payload, options) {

    if (!payload || typeof payload !== 'object') {
        throw new Error('Invalid payload passed to create JWT token');
    }

    var algorithm = options.algorithm;
    var supportedAlgorithms = jwtHelper.SUPPORTED_ALGORITHMS;
    if (supportedAlgorithms.indexOf(algorithm) === -1) {
        throw new Error(StringUtils.format('JWT Algorithm {0} not supported', algorithm));
    }

    var header = {
        "alg": options.algorithm,
        "type": "JWT",
        "kid" : options.kid
    };

    var headerBase64 = Encoding.toBase64(new Bytes(JSON.stringify(header)));
    var headerBase64UrlEncoded = jwtHelper.toBase64UrlEncoded(headerBase64);

    var payloadBase64 = Encoding.toBase64(new Bytes(JSON.stringify(payload)));
    var payloadBase64UrlEncoded = jwtHelper.toBase64UrlEncoded(payloadBase64);

    var signature = headerBase64UrlEncoded + "." + payloadBase64UrlEncoded;

    var privateKeyOrSecret;
    if(options.privateKeyOrSecret && typeof options.privateKeyOrSecret === 'string') {
        privateKeyOrSecret = options.privateKeyOrSecret;
    }

    if (!privateKeyOrSecret) {
        throw new Error('Cannot sign JWT token as private key or secret not supplied');
    }

    var signFunction = JWTAlgoToSignMapping[algorithm];
    if (!signFunction) {
        throw new Error(StringUtils.format('No sign function found for supplied algorithm {0}', algorithm));
    }

    var jwtSignature = signFunction(signature, privateKeyOrSecret, algorithm);
    var jwtSignatureUrlEncoded = jwtHelper.toBase64UrlEncoded(jwtSignature);

    var jwtToken = headerBase64UrlEncoded + '.' + payloadBase64UrlEncoded + '.' + jwtSignatureUrlEncoded;

    return jwtToken;
}


function signWithRSA(input, privateKey, algorithm) {
    var contentToSignInBytes = new Bytes(input);

    var apiSig = new Signature();
    var signedBytes = apiSig.signBytes(contentToSignInBytes, new Bytes(privateKey), JWTAlgoToSFCCMapping[algorithm]);

    return Encoding.toBase64(signedBytes);
}

function signWithHMAC(input, secret, algorithm) {
    var mac = new Mac(JWTAlgoToSFCCMapping[algorithm]);
    var inputInBytes = new Bytes(input);
    var secretInBytes = new Bytes(secret);

    var output = mac.digest(inputInBytes, secretInBytes);

    return Encoding.toBase64(output);
}
module.exports.signJWT = signJWT;
