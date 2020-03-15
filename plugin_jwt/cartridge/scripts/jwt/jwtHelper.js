var JWT_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;
var SUPPORTED_ALGORITHMS = ['RS256'];

function isValidJWT(jwt) {
    return JWT_REGEX.test(jwt);
}

var JWTAlgoToSFCCMapping = {
    "RS256" : "SHA256withRSA"
};

function toBase64UrlEncoded(input) {
    return input.replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/\=+$/m, '');
}

module.exports.isValidJWT = isValidJWT;
module.exports.toBase64UrlEncoded = toBase64UrlEncoded;
module.exports.SUPPORTED_ALGORITHMS = SUPPORTED_ALGORITHMS;
module.exports.JWTAlgoToSFCCMapping = JWTAlgoToSFCCMapping;
