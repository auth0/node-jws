const base64url = require('base64url');
const crypto = require('crypto');
const test = require('tap').test;
const jws = require('..');

test('HS256 algorithm, signing', function (t) {
  const testString = 'oh hey';
  const secret = 'sup';
  const expectedHeader = { alg: 'HS256' };

  const jwsObject = jws.sign(testString, secret);
  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);

  t.same(payload, testString, 'payload should match test string');
  t.same(header, expectedHeader, 'header should match expectation');
  t.end();
});

test('HS256 algorithm, verifying', function (t) {
  const testString = 'oh hey';
  const secret = 'sup';
  const jwsObject = jws.sign(testString, secret);

  const verified = jws.verify(jwsObject, secret);
  t.ok(verified, 'should be verified');

  const notVerified = jws.verify(jwsObject, 'some other thing');
  t.notOk(notVerified, 'should not be verified');
  t.end();
});

