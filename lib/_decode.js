/* global Buffer, module */
/* jshint laxbreak:true */

const toString = require('./tostring');

const JWS_REGEX = (function () {
  const BASE64_PART = /[a-zA-Z0-9\-_]+/;

  return new RegExp(
    '^'
    + BASE64_PART.source
    + '\\.'
    + BASE64_PART.source
    + '\\.'
    + '(' + BASE64_PART.source + ')?'
    + '$'
  );
})();

function tryParse(thing) {
  try { return JSON.parse(thing); }
  catch (e) { return undefined; }
}

function utf8(input) {
  const result = new Buffer(input, 'base64').toString('utf8');
  return result;
}

function jwsParts(jws) {
  jws = toString(jws);

  if (!JWS_REGEX.test(jws)) {
    return null;
  }

  const parts = jws.split('.');  
  return parts;
}

function headerFromParts(parts) {
  var header = parts[0];
  header = utf8(header);
  header = tryParse(header);
  return header;
}

function payloadFromParts(parts, json) {
  var payload = parts[1];
  payload = utf8(payload);

  if (json) {
    payload = JSON.parse(payload);
  }

  return payload;
}

function securedInputFromParts(parts) {
  return parts[0] + '.' + parts[1];
}

function signatureFromParts(parts) {
  return parts[2];
}

module.exports = jwsParts;
module.exports.header = headerFromParts;
module.exports.payload = payloadFromParts;
module.exports.input = securedInputFromParts;
module.exports.signature = signatureFromParts;
