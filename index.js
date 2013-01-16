const util = require('util');
const base64url = require('base64url');
const crypto = require('crypto');

exports.sign = function _jwsSign() {
  const opts = {};
  if (typeof arguments[0] === 'object') {
    return jwsSign(arguments[0]);
  }
  if (arguments.length === 2) {
    opts.header = { alg : 'HS256' };
    opts.payload = arguments[0];
    opts.secret = arguments[1];
    return jwsSign(opts);
  }
}

function jwsSign(opts) {
  var payload = opts.payload;
  if (typeof opts.payload === 'object')
    payload = JSON.stringify(opts.payload);
  const header = JSON.stringify(opts.header);
  const hmac = crypto.createHmac('SHA256', opts.secret);
  hmac.update(payload);
  const signature = hmac.digest('base64');
  return util.format(
    '%s.%s.%s',
    base64url(header),
    base64url(payload),
    base64url.fromBase64(signature));
}