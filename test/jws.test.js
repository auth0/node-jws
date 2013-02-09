const fs = require('fs');
const base64url = require('base64url');
const crypto = require('crypto');
const test = require('tap').test;
const jws = require('..');

const testRSAPrivateKey = fs.readFileSync(__dirname + '/rsa-private.pem').toString();
const testRSAPublicKey = fs.readFileSync(__dirname + '/rsa-public.pem').toString();
const testRSAWrongPublicKey = fs.readFileSync(__dirname + '/rsa-wrong-public.pem').toString();
const testEC256PrivateKey = fs.readFileSync(__dirname + '/ec256-private.pem').toString();
const testEC256PublicKey = fs.readFileSync(__dirname + '/ec256-public.pem').toString();
const testEC256WrongPublicKey = fs.readFileSync(__dirname + '/ec256-wrong-public.pem').toString();
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

  const jwsObject = jws.sign(expectedPayload, testRSAPrivateKey);
  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);

  t.same(payload, expectedPayload, 'payload should match');
  t.same(header, expectedHeader, 'header should match');
  t.end();
});

test('RS256 algorithm implicit, verifying', function (t) {
  const payload = 'hallo';
  const jwsObject = jws.sign(payload, testRSAPrivateKey);

  const verified = jws.verify(jwsObject, testRSAPublicKey);
  t.ok(verified, 'should be verified');

  const notVerified = jws.verify(jwsObject, testRSAWrongPublicKey);
  t.notOk(notVerified, 'should not be verified');
  t.end();
});

test('ES256 algorithm implicit, signing', {skip: true}, function (t) {
  const expectedPayload = { spumpkins: 'siamese dream' };
  const expectedHeader = { alg: 'EC256' };

  const jwsObject = jws.sign(expectedPayload, testEC256PrivateKey);
  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);

  t.same(payload, expectedPayload, 'payload should match');
  t.same(header, expectedHeader, 'header should match');
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

test('no algorithm explicit, signing', function (t) {
  const secret = RSA_INDICATOR;
  const expectedPayload = 'oh hey';
  const expectedHeader = {
    alg: 'none',
    typ: 'JWT',
    hiFives: true
  };
  const jwsObject = jws.sign({
    header: expectedHeader,
    payload: expectedPayload,
  });

  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);

  t.same(payload, expectedPayload, 'payload should match');
  t.same(header, expectedHeader, 'header should match');
  t.ok(jwsObject.match(/\.$/), 'should end with a dot');
  t.end();
});

test('no algorithm explicit, signing', function (t) {
  const secret = RSA_INDICATOR;
  const expectedPayload = 'oh hey';
  const expectedHeader = {
    alg: 'none',
    typ: 'JWT',
    hiFives: true
  };
  const jwsObject = jws.sign({
    header: expectedHeader,
    payload: expectedPayload,
  });

  const parts = jwsObject.split('.');
  const header = JSON.parse(base64url.decode(parts[0]));
  const payload = base64url.decode(parts[1]);

  t.same(payload, expectedPayload, 'payload should match');
  t.same(header, expectedHeader, 'header should match');
  t.ok(jwsObject.match(/\.$/), 'should end with a dot');
  t.end();
});

test('no algorithm explicit, verifying', function (t) {
  const secret = RSA_INDICATOR;
  const expectedPayload = 'oh hey';
  const expectedHeader = {
    alg: 'none',
    typ: 'JWT',
    hiFives: true
  };

  const jwsObject = jws.sign({
    header: expectedHeader,
    payload: expectedPayload,
  });

  t.ok(jws.verify(jwsObject, 'anything at all'), 'should verify');
  t.end();
});

test('verifying without a secret or key should fail early', function (t) {
  const jwsObject = jws.sign('wut', 'lol');
  try {
    jws.verify(jwsObject);
    t.fail('should have thrown');
  } catch(exception) {
    t.ok(exception instanceof TypeError, 'should be a type error');
    t.pass('threw exception');
  }
  t.end();
});

test('verifying without a proper jwsObject should fail', function (t) {
  try {
    jws.verify('not a jws', 'secret');
    t.fail('should have thrown');
  } catch(exception) {
    console.dir(exception);
    t.ok(exception instanceof TypeError, 'should be a type error');
    t.pass('threw exception');
  }
  t.end();
});

test('jws.decode: normal', function (t) {
  const expectedPayload = { spumpkins: 'siamese dream' };
  const expectedHeader = { alg: 'HS256' };
  const jwsObject = jws.sign(expectedPayload, 'shhhhhh');
  const parts = jws.decode(jwsObject);
  t.same(parts.header, expectedHeader, 'should have right header');
  t.same(JSON.parse(parts.payload), expectedPayload, 'should have right payload');
  t.end();
});

test('jws.decode: specify JWT type', function (t) {
  const expectedPayload = { spumpkins: 'siamese dream' };
  const expectedHeader = { alg: 'HS256', typ: 'JWT' };
  const jwsObject = jws.sign({
    header: expectedHeader,
    payload: expectedPayload,
    secret: 'shhhhhh'
  });
  const parts = jws.decode(jwsObject);
  t.same(parts.header, expectedHeader, 'should have right header');
  t.same(parts.payload, expectedPayload, 'should have right payload');
  t.end();
});
