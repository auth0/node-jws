const fs = require('fs');
const base64url = require('base64url');
const crypto = require('crypto');
const test = require('tap').test;
const jws = require('..');

function readfile(path) {
  return fs.readFileSync(__dirname + '/' + path).toString();
}

const rsaPrivateKey = readfile('rsa-private.pem');
const rsaPublicKey = readfile('rsa-public.pem');
const rsaWrongPublicKey = readfile('rsa-wrong-public.pem');
const ecdsaPrivateKey = {
  '256': readfile('ec256-private.pem'),
  '384': readfile('ec384-private.pem'),
  '512': readfile('ec512-private.pem'),
};
const ecdsaPublicKey = {
  '256': readfile('ec256-public.pem'),
  '384': readfile('ec384-public.pem'),
  '512': readfile('ec512-public.pem'),
};
const ecdsaWrongPublicKey = {
  '256': readfile('ec256-wrong-public.pem'),
  '384': readfile('ec384-wrong-public.pem'),
  '512': readfile('ec512-wrong-public.pem'),
};

const BITS = ['256', '384', '512'];
const CURVES = {
  '256': '256',
  '384': '384',
  '512': '521',
};

BITS.forEach(function (bits) {
  test('HMAC using SHA-'+bits+' hash algorithm', function (t) {
    const header = { alg: 'HS'+bits, typ: 'JWT' };
    const payload = {name: 'oh hey', value: ['one', 2, 3]};
    const secret = 'sup';
    const jwsObj = jws.sign({
      header: header,
      payload: payload,
      secret: secret
    });
    const parts = jws.decode(jwsObj);
    t.ok(jws.verify(jwsObj, secret), 'should verify');
    t.notOk(jws.verify(jwsObj, 'something else'), 'should not verify');
    t.same(parts.payload, payload, 'should match payload');
    t.same(parts.header, header, 'should match header');
    t.end();
  });
});

BITS.forEach(function (bits) {
  test('RSASSA using SHA-'+bits+' hash algorithm', function (t) {
    const header = { alg: 'RS'+bits };
    const payload = {name: 'oh hey', value: ['one', 2, 3]};
    const privateKey = rsaPrivateKey;
    const publicKey = rsaPublicKey;
    const wrongPublicKey = rsaWrongPublicKey;
    const jwsObj = jws.sign({
      header: header,
      payload: payload,
      privateKey: privateKey
    });
    const parts = jws.decode(jwsObj, { json: true });
    t.ok(jws.verify(jwsObj, publicKey), 'should verify');
    t.notOk(jws.verify(jwsObj, wrongPublicKey), 'should not verify');
    t.same(parts.payload, payload, 'should match payload');
    t.same(parts.header, header, 'should match header');
    t.end();
  });
});

BITS.forEach(function (bits) {
  const curve = CURVES[bits];
  test('ECDSA using P-'+curve+' curve and SHA-'+bits+' hash algorithm', function (t) {
    const header = { alg: 'ES'+bits };
    const payload = 'oh hey';
    const privateKey = ecdsaPrivateKey['256'];
    const publicKey = ecdsaPublicKey['256'];
    const wrongPublicKey = ecdsaWrongPublicKey['256'];
    const jwsObj = jws.sign({
      header: header,
      payload: payload,
      privateKey: privateKey
    });
    const parts = jws.decode(jwsObj);
    t.ok(jws.verify(jwsObj, publicKey), 'should verify');
    t.notOk(jws.verify(jwsObj, wrongPublicKey), 'should not verify');
    t.same(parts.payload, payload, 'should match payload');
    t.same(parts.header, header, 'should match header');
    t.end();
  });
});

test('No digital signature or MAC value included', function (t) {
    const header = { alg: 'none' };
    const payload = 'oh hey';
    const jwsObj = jws.sign({
      header: header,
      payload: payload,
    });
    const parts = jws.decode(jwsObj);
    t.ok(jws.verify(jwsObj), 'should verify');
    t.ok(jws.verify(jwsObj, 'anything'), 'should still verify');
    t.same(parts.payload, payload, 'should match payload');
    t.same(parts.header, header, 'should match header');
    t.end();
});
