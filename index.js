const util = require('util');
const base64url = require('base64url');
const crypto = require('crypto');

exports.sign = function jwsSign() {
  var opts, header, payload, secretOrKey;
  if (arguments.length === 2) {
    secretOrKey = arguments[1];
    header = {
      alg: algorithmFromSecret(secretOrKey)
    };
    return jwsSign({
      header: header,
      payload: arguments[0],
      secret: secretOrKey,
    });
  }

  if (arguments.length === 1) {
    opts = arguments[0];
    header = opts.header;
    payload = opts.payload;
    if (typeof payload === 'object')
      payload = JSON.stringify(payload);
    const signers = {
      HS256: jwsHS256Sign,
      RS256: jwsRS256Sign,
      EC256: jwsEC256Sign,
      none: jwsNoneSign,
    };
    const signerFn = signers[header.alg];
    return signerFn(header, payload, (opts.secret || opts.key))
  }
}

function jwsSecuredInput(header, payload) {
  const encodedHeader = base64url(header);
  const encodedPayload = base64url(payload);
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

function algorithmFromSecret(secretOrKey) {
  secretOrKey = secretOrKey.toString();
  const RSA_INDICATOR = '-----BEGIN RSA PRIVATE KEY-----';
  const EC_INDICATOR = '-----BEGIN EC PRIVATE KEY-----';
  if (secretOrKey.indexOf(RSA_INDICATOR) > -1)
    return 'RS256';
  if (secretOrKey.indexOf(EC_INDICATOR) > -1)
    return 'EC256';
  return 'HS256';
}

function jwsNoneSign(header, payload) {
  header = JSON.stringify(header);
  return jwsOutput(header, payload, '');
}

// The latest version of openssl doesn't yet support `ecdsa-with-sha256`
// as a message digest algorithm, only `ecdsa-with-sha1` (despite the
// fact it supports both separately). Once that is implemented, we can
// implement this.
function jwsEC256Sign(header, payload, key) {
  throw "Not implemented, yet";
}

function jwsRS256Sign(header, payload, key) {
  header = JSON.stringify(header);
  const signature = createRS256Signature(header, payload, key);
  return jwsOutput(header, payload, signature);
}

function createRS256Signature(header, payload, key) {
  const signer = crypto.createSign('RSA-SHA256', key);
  const securedInput = jwsSecuredInput(header, payload);
  const signature = (signer.update(securedInput), signer.sign(key, 'base64'));
  return base64url.fromBase64(signature);
}

function jwsHS256Sign(header, payload, secret) {
  header = JSON.stringify(header);
  const signature = createHS256Signature(header, payload, secret);
  return jwsOutput(header, payload, signature);
}

function createHS256Signature(header, payload, secret) {
  const hmac = crypto.createHmac('SHA256', secret);
  const securedInput = jwsSecuredInput(header, payload);
  const signature = (hmac.update(securedInput), hmac.digest('base64'));
  return base64url.fromBase64(signature);
}

function jwsOutput(header, payload, signature) {
  return util.format(
    '%s.%s.%s',
    base64url(header),
    base64url(payload),
    signature);
}

exports.verify = function jwsVerify(jwsObject, secretOrKey) {
  const parts = jwsObject.split('.');
  const encodedHeader = parts[0];
  const encodedPayload = parts[1];
  const encodedSignature = parts[2];
  const rawHeader = base64url.decode(encodedHeader);
  const payload = base64url.decode(encodedPayload);
  const header = JSON.parse(rawHeader);
  const verifiers = {
    HS256: jwsHS256Verify,
    RS256: jwsRS256Verify,
    none: jwsNoneVerify,
  };
  const verifierFn = verifiers[header.alg];
  return verifierFn(rawHeader, payload, secretOrKey, encodedSignature)
}

function jwsHS256Verify(header, payload, secret, expectedSignature) {
  const calculatedSignature =
    createHS256Signature(header, payload, secret);
  return expectedSignature === calculatedSignature;
}

function jwsRS256Verify(header, payload, publicKey, signature) {
  const verifier = crypto.createVerify('RSA-SHA256');
  const securedInput = jwsSecuredInput(header, payload);
  signature = base64url.toBase64(signature);
  verifier.update(securedInput);
  return verifier.verify(publicKey, signature, 'base64');
}

function jwsNoneVerify() { return true };
exports.validate = exports.verify;