/*global module*/
const DataStream = require('./data-stream');
const jwa = require('jwa');
const Stream = require('stream');
const util = require('util');

const _decode = require('./_decode');

function isValidJws(string) {
  const parts = _decode(string);
  const valid = !!(parts && _decode.header(parts));
  return valid;
}

function jwsVerify(jwsSig, algorithm, secretOrKey) {
  if (!algorithm) {
    var err = new Error("Missing algorithm parameter for jws.verify");
    err.code = "MISSING_ALGORITHM";
    throw err;
  }

  const parts = _decode(jwsSig);
  if (!parts) {
    return false;
  }

  const signature = _decode.signature(parts);
  const securedInput = _decode.input(parts);
  const algo = jwa(algorithm);
  return algo.verify(securedInput, signature, secretOrKey);
}

function jwsDecode(jwsSig, opts) {
  const parts = _decode(jwsSig);

  if (!parts) {
    return null;
  }

  const header = _decode.header(parts);

  if (!header) {
    return null;
  }

  const payload = _decode.payload(parts, header.typ === 'JWT' || (opts && opts.json));
  const signature = _decode.signature(parts);

  return {
    header: header,
    payload: payload,
    signature: signature
  };
}

function VerifyStream(opts) {
  opts = opts || {};
  const secretOrKey = opts.secret||opts.publicKey||opts.key;
  const secretStream = new DataStream(secretOrKey);
  this.readable = true;
  this.algorithm = opts.algorithm;
  this.encoding = opts.encoding;
  this.secret = this.publicKey = this.key = secretStream;
  this.signature = new DataStream(opts.signature);
  this.secret.once('close', function () {
    if (!this.signature.writable && this.readable)
      this.verify();
  }.bind(this));

  this.signature.once('close', function () {
    if (!this.secret.writable && this.readable)
      this.verify();
  }.bind(this));
}
util.inherits(VerifyStream, Stream);
VerifyStream.prototype.verify = function verify() {
  const valid = jwsVerify(this.signature.buffer, this.algorithm, this.key.buffer);
  const obj = jwsDecode(this.signature.buffer, this.encoding);
  this.emit('done', valid, obj);
  this.emit('data', valid);
  this.emit('end');
  this.readable = false;
  return valid;
};

VerifyStream.decode = jwsDecode;
VerifyStream.isValid = isValidJws;
VerifyStream.verify = jwsVerify;

module.exports = VerifyStream;
