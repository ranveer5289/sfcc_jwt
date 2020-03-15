var sign = require('*/cartridge/scripts/jwt/sign.js');
var verify = require('*/cartridge/scripts/jwt/verify.js');
var decode = require('*/cartridge/scripts/jwt/decode.js');

module.exports.sign = sign.signJWT;
module.exports.verify = verify.verifyJWT;
module.exports.decode = decode.decodeJWT;

