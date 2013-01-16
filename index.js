const util = require('util');
const base64url = require('base64url');
const crypto = require('crypto');

exports.sign = function jwsSign() {
  const opts = {};
  if (typeof arguments[0] === 'object')
    return jwsSign(arguments[0]);
  if (arguments.length === 2) {
    opts.header = { alg : 'HS256' };
    opts.payload = arguments[0];
    opts.secret = arguments[1];
    return jwsHS256Sign(opts);
  }
}

function jwsHS256Sign(opts) {
  var payload = opts.payload;
  if (typeof opts.payload === 'object')
    payload = JSON.stringify(opts.payload);
  const secret = opts.secret;
  const header = JSON.stringify(opts.header);
  const signature = createHS256Signature(header, payload, secret);
  return jwsOutput(header, payload, signature);
}

function jwsOutput(header, payload, signature) {
  return util.format(
    '%s.%s.%s',
    base64url(header),
    base64url(payload),
    signature);
}

function createHS256Signature(header, payload, secret) {
  const hmac = crypto.createHmac('SHA256', secret);
  const encodedHeader = base64url(header);
  const encodedPayload = base64url(payload);
  hmac.update(encodedHeader);
  hmac.update('.');
  hmac.update(encodedPayload);
  const signature = hmac.digest('base64');
  return base64url.fromBase64(signature);
}

exports.verify = function jwsVerify(jwsObject, keyOrSecret) {
  const parts = jwsObject.split('.');
  const encodedHeader = parts[0];
  const encodedPayload = parts[1];
  const encodedSignature = parts[2];
  const rawHeader = base64url.decode(encodedHeader);
  const payload = base64url.decode(encodedPayload);
  const header = JSON.parse(rawHeader);
  if (header.alg === 'HS256')
    return jwsHS256Verify(rawHeader, payload, keyOrSecret, encodedSignature)
}

function jwsHS256Verify(header, payload, secret, expectedSignature) {
  const calculatedSignature =
    createHS256Signature(header, payload, secret);
  return expectedSignature === calculatedSignature;
}