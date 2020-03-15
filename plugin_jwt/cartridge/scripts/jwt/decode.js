var jwtHelper = require('*/cartridge/scripts/jwt/jwtHelper');
var Logger = require('dw/system/Logger');

function decodeJWT(jwt, options) {
    var options = options || {};

    if (!jwtHelper.isValidJWT(jwt)) {
        return null;
    }

    var header = getHeaderFromJWT(jwt);
    if(!header) {
        return null;
    }

    var payload = getPayloadFromJWT(jwt);
    if (!payload) {
        return null;
    }

    var signature = getSignatureFromJWT(jwt);
    if (!signature) {
        return null;
    }

    return {
        header: header,
        payload: payload,
        signature: signature
    }
}

function getHeaderFromJWT(jwt) {
    var encodedHeader = jwt.split('.')[0];
    var Encoding = require('dw/crypto/Encoding');

    var decodedHeader = Encoding.fromBase64(encodedHeader).toString();
    var jwtHeaderObj = {};

    try {
        jwtHeaderObj = JSON.parse(decodedHeader);
    } catch (error) {
        Logger.error('Error parsing jwt token header');
        return null;
    }

    return jwtHeaderObj;
}

function getPayloadFromJWT(jwt) {
    var encodedPayload = jwt.split('.')[1];
    var Encoding = require('dw/crypto/Encoding');

    var decodedPayload = Encoding.fromBase64(encodedPayload).toString();
    var jwtPayloadObj = {};

    try {
        jwtPayloadObj = JSON.parse(decodedPayload);
    } catch (error) {
        Logger.error('Error parsing jwt token payload');
        return null;
    }

    return jwtPayloadObj;
}

function getSignatureFromJWT(jwt) {
    return jwt.split('.')[2];
}

module.exports.decodeJWT = decodeJWT;

