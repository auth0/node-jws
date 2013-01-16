const base64url = require('base64url');
const crypto = require('crypto');
const test = require('tap').test;
const jws = require('..');

test('HS256 algorithm', function (t) {
  const testString = 'oh hey';
  const secret = 'sup';
  const expectedHeader = { alg: 'HS256' };

  const jwsObject = jws.sign(testString, secret);
  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);
  const signature = base64url.toBase64(parts[2]);

  const hmac = crypto.createHmac('SHA256', secret);
  hmac.update(testString);
  const expectedSignature = hmac.digest('base64');

  t.same(payload, testString, 'payload should match test string');
  t.same(header, expectedHeader, 'header should match expectation');
  t.same(signature, expectedSignature, 'signatures should match');
  t.end();
});


