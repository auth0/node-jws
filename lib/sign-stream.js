/*global module*/
var Buffer = require('safe-buffer').Buffer;
var DataStream = require('./data-stream');
var jwa = require('jwa');
var Stream = require('stream');
var toString = require('./tostring');
var util = require('util');

function base64url(string, encoding) {
  return Buffer
    .from(string, encoding)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function jwsSecuredInput(header, payload, encoding) {
  encoding = encoding || 'utf8';
  var encodedHeader = base64url(toString(header), 'binary');
  var encodedPayload = base64url(toString(payload), encoding);
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

function jwsSign(opts) {
  var header = opts.header;
  var payload = opts.payload;
  var secretOrKey = opts.secret || opts.privateKey;
  var encoding = opts.encoding;
  var algo = opts.jwa ? opts.jwa(header.alg) : jwa(header.alg);
  // if the supplied jwa callback did not return a value, attempt to fall back to jwa
  if ((!algo || !algo.sign) && opts.jwa) {
    algo = jwa(header.alg);
  }
  var securedInput = jwsSecuredInput(header, payload, encoding);
  try {
    return Promise.resolve(algo.sign(securedInput, secretOrKey))
        .then(function (signature) {
          return util.format('%s.%s', securedInput, signature);
        });
  } catch (e) {
    return Promise.reject(e);
  }
}

function SignStream(opts) {
  var secret = opts.secret||opts.privateKey||opts.key;
  var secretStream = new DataStream(secret);
  this.jwa = opts.jwa || jwa;
  this.readable = true;
  this.header = opts.header;
  this.encoding = opts.encoding;
  this.secret = this.privateKey = this.key = secretStream;
  this.payload = new DataStream(opts.payload);
  this.secret.once('close', function () {
    if (!this.payload.writable && this.readable)
      this.sign();
  }.bind(this));

  this.payload.once('close', function () {
    if (!this.secret.writable && this.readable)
      this.sign();
  }.bind(this));
}
util.inherits(SignStream, Stream);

SignStream.prototype.sign = function sign() {
  try {
    var self = this;
    return jwsSign({
      header: this.header,
      payload: this.payload.buffer,
      secret: this.secret.buffer,
      encoding: this.encoding,
      jwa: this.jwa
    }).then(function (signature) {
      self.emit('done', signature);
      self.emit('data', signature);
      self.emit('end');
      self.readable = false;
      return signature;
    }).catch(function (e) {
      self.readable = false;
      self.emit('error', e);
      self.emit('close');
    });
  } catch (e) {
    this.readable = false;
    this.emit('error', e);
    this.emit('close');
  }
};

SignStream.sign = jwsSign;

module.exports = SignStream;
