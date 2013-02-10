const util = require('util');
const base64url = require('base64url');
const crypto = require('crypto');
const jwa = require('jwa');

function toString(obj) {
  if (typeof obj === 'string')
    return obj;
  if (typeof obj === 'number' || Buffer.isBuffer(obj))
    return obj.toString();
  return JSON.stringify(obj);
}

function jwsSecuredInput(header, payload) {
  const encodedHeader = base64url(toString(header));
  const encodedPayload = base64url(toString(payload));
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

function jwsSign(opts) {
  const header = opts.header;
  const payload = opts.payload;
  const secretOrKey = opts.secret || opts.privateKey;
  const algo = jwa(header.alg);
  const securedInput = jwsSecuredInput(header, payload);
  const signature = algo.sign(securedInput, secretOrKey);
  return util.format('%s.%s', securedInput, signature);
}

function headerFromJWS(jwsSig) {
  const encodedHeader = jwsSig.split('.', 1)[0];
  return JSON.parse(base64url.decode(encodedHeader));
}

function securedInputFromJWS(jwsSig) {
  return jwsSig.split('.', 2).join('.');
}

function algoFromJWS(jwsSig) {
  return headerFromJWS(jwsSig).alg;
}

function signatureFromJWS(jwsSig) {
  return jwsSig.split('.')[2];
}

function payloadFromJWS(jwsSig) {
  const payload = jwsSig.split('.')[1];
  return base64url.decode(payload);
}

function isValidJws(string) {
  const jwsObjRe = /.+\..+\..*/;
  if (typeof string !== 'string')
    return false;
  if (!string.match(jwsObjRe))
    return false;
  return true;
}

function jwsVerify(jwsSig, secretOrKey) {
  const signature = signatureFromJWS(jwsSig);
  const securedInput = securedInputFromJWS(jwsSig);
  const algo = jwa(algoFromJWS(jwsSig));
  return algo.verify(securedInput, signature, secretOrKey);
}

function jwsDecode(jwsSig, opts) {
  opts = opts || {};
  const header = headerFromJWS(jwsSig);
  var payload = payloadFromJWS(jwsSig);
  if (header.typ === 'JWT' || opts.json)
    payload = JSON.parse(payload);
  return {
    header: header,
    payload: payload,
    signature: signatureFromJWS(jwsSig),
  }
}

exports.sign = jwsSign;
exports.verify = jwsVerify;
exports.decode = jwsDecode;


function algorithmFromSecret(secretOrKey) {
  secretOrKey = secretOrKey.toString();
  const RSA_INDICATOR = '-----BEGIN RSA PRIVATE KEY-----';
  const EC_INDICATOR = '-----BEGIN EC PRIVATE KEY-----';
  if (secretOrKey.indexOf(RSA_INDICATOR) > -1)
    return 'RS';
  if (secretOrKey.indexOf(EC_INDICATOR) > -1)
    return 'EC';
  return 'HS';
}


