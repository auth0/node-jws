const Stream = require('stream');
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
  jwsSig = toString(jwsSig);
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

exports.createSign = function createSign(opts) {
  return new StreamSign(opts);
};
exports.createVerify = function createVerify(opts) {
  return new StreamVerify(opts);
};

function StreamSign(opts) {
  const secret = opts.secret||opts.privateKey||opts.key;
  const secretStream = new StreamData(secret);
  this.readable = true;
  this.header = opts.header;
  this.secret = this.privateKey = this.key = secretStream;
  this.payload = new StreamData(opts.payload);
  this.secret.once('close', function () {
    if (!this.payload.writable && this.readable)
      this.sign();
  }.bind(this));

  this.payload.once('close', function () {
    if (!this.secret.writable && this.readable)
      this.sign();
  }.bind(this));
}
util.inherits(StreamSign, Stream);
StreamSign.prototype.sign = function sign() {
  const signature = jwsSign({
    header: this.header,
    payload: this.payload.buffer,
    secret: this.secret.buffer,
  });
  this.emit('done', signature);
  this.emit('data', signature);
  this.emit('end');
  this.readable = false;
  return signature;
};

function StreamVerify(opts) {
  opts = opts || {};
  const secretOrKey = opts.secret||opts.publicKey||opts.key;
  const secretStream = new StreamData(secretOrKey);
  this.readable = true;
  this.secret = this.publicKey = this.key = secretStream;
  this.signature = new StreamData(opts.signature);
  this.secret.once('close', function () {
    if (!this.signature.writable && this.readable)
      this.verify();
  }.bind(this));

  this.signature.once('close', function () {
    if (!this.secret.writable && this.readable)
      this.verify();
  }.bind(this));
}
util.inherits(StreamVerify, Stream);
StreamVerify.prototype.verify = function verify() {
  const verified = jwsVerify(this.signature.buffer, this.key.buffer);
  this.emit('done', verified);
  this.emit('data', verified);
  this.emit('end');
  this.readable = false;
  return verified;
};

function StreamData(data) {
  this.buffer = Buffer(data||0);
  this.writable = true;
  this.readable = true;
  if (!data)
    return this;
  if (typeof data.pipe === 'function')
    data.pipe(this);
  else if (data.length) {
    this.writable = false;
    process.nextTick(function () {
      this.buffer = data;
      this.emit('end', data);
      this.readable = false;
      this.emit('close');
    }.bind(this));
  }
};
util.inherits(StreamData, Stream);

StreamData.prototype.write = function write(data) {
  this.buffer = Buffer.concat([this.buffer, Buffer(data)]);
  this.emit('data', data);
};

StreamData.prototype.end = function end(data) {
  if (data)
    this.write(data);
  this.emit('end', data);
  this.emit('close');
  this.writable = false;
  this.readable = false;
};