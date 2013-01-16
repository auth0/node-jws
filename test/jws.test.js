const fs = require('fs');
const base64url = require('base64url');
const crypto = require('crypto');
const test = require('tap').test;
const jws = require('..');

const testPrivateKey = fs.readFileSync('./private.pem').toString();
const testPublicKey = fs.readFileSync('./public.pem').toString();
const testWrongPublicKey = fs.readFileSync('./wrong-public.pem').toString();

test('HS256 algorithm implicit, signing', function (t) {
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

test('HS256 algorithm implicit, verifying', function (t) {
  const testString = 'oh hey';
  const secret = 'sup';
  const jwsObject = jws.sign(testString, secret);

  const verified = jws.verify(jwsObject, secret);
  t.ok(verified, 'should be verified');

  const notVerified = jws.verify(jwsObject, 'some other thing');
  t.notOk(notVerified, 'should not be verified');
  t.end();
});

test('RS256 algorithm implicit, signing', function (t) {
  const testString = 'oh hi friends!';
  const expectedHeader = { alg: 'RS256' };

  const jwsObject = jws.sign(testString, testPrivateKey);
  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);

  t.same(payload, testString, 'payload should match test string');
  t.same(header, expectedHeader, 'header should match expectation');
  t.end();
});

test('RS256 algorithm implicit, verifying', function (t) {
  const testString = 'hallo';
  const jwsObject = jws.sign(testString, testPrivateKey);

  const verified = jws.verify(jwsObject, testPublicKey);
  t.ok(verified, 'should be verified');

  const notVerified = jws.verify(jwsObject, testWrongPublicKey);
  t.notOk(notVerified, 'should not be verified');
  t.end();
});
