const fs = require('fs');
const base64url = require('base64url');
const crypto = require('crypto');
const test = require('tap').test;
const jws = require('..');

const testPrivateKey = fs.readFileSync('./private.pem').toString();
const testPublicKey = fs.readFileSync('./public.pem').toString();
const testWrongPublicKey = fs.readFileSync('./wrong-public.pem').toString();
const RSA_INDICATOR = '-----BEGIN RSA PRIVATE KEY-----';

test('HS256 algorithm implicit, signing', function (t) {
  const secret = 'sup';
  const expectedPayload = 'oh hey';
  const expectedHeader = { alg: 'HS256' };

  const jwsObject = jws.sign(expectedPayload, secret);
  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);

  t.same(payload, expectedPayload, 'payload should match');
  t.same(header, expectedHeader, 'header should match');
  t.end();
});

test('HS256 algorithm implicit, verifying', function (t) {
  const payload = 'oh hey';
  const secret = 'sup';
  const jwsObject = jws.sign(payload, secret);

  const verified = jws.verify(jwsObject, secret);
  t.ok(verified, 'should be verified');

  const notVerified = jws.verify(jwsObject, 'some other thing');
  t.notOk(notVerified, 'should not be verified');
  t.end();
});

test('RS256 algorithm implicit, signing', function (t) {
  const expectedPayload = 'oh hi friends!';
  const expectedHeader = { alg: 'RS256' };

  const jwsObject = jws.sign(expectedPayload, testPrivateKey);
  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);

  t.same(payload, expectedPayload, 'payload should match');
  t.same(header, expectedHeader, 'header should match');
  t.end();
});

test('RS256 algorithm implicit, verifying', function (t) {
  const payload = 'hallo';
  const jwsObject = jws.sign(payload, testPrivateKey);

  const verified = jws.verify(jwsObject, testPublicKey);
  t.ok(verified, 'should be verified');

  const notVerified = jws.verify(jwsObject, testWrongPublicKey);
  t.notOk(notVerified, 'should not be verified');
  t.end();
});

test('HS256 algorithm explicit, signing', function (t) {
  const secret = RSA_INDICATOR;
  const expectedPayload = 'oh hey';
  const expectedHeader = {
    alg: 'HS256',
    typ: 'JWT',
    hiFives: true
  };
  const jwsObject = jws.sign({
    header: expectedHeader,
    payload: expectedPayload,
    secret: RSA_INDICATOR,
  });
  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);

  t.same(payload, expectedPayload, 'payload should match');
  t.same(header, expectedHeader, 'header should match');
  t.end();
});
