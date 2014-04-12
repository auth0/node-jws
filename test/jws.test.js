const fs = require('fs');
const base64url = require('base64url');
const crypto = require('crypto');
const test = require('tap').test;
const jws = require('..');

function readfile(path) {
  return fs.readFileSync(__dirname + '/' + path).toString();
}

function readstream(path) {
  return fs.createReadStream(__dirname + '/' + path);
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

test('Streaming sign: HMAC', function (t) {
  const dataStream = readstream('data.txt');
  const secret = 'shhhhh';
  const sig = jws.createSign({
    header: { alg: 'HS256' },
    secret: secret
  });
  dataStream.pipe(sig.payload);
  sig.on('done', function (signature) {
    t.ok(jws.verify(signature, secret), 'should verify');
    t.end();
  });
});

test('Streaming sign: RSA', function (t) {
  const dataStream = readstream('data.txt');
  const privateKeyStream = readstream('rsa-private.pem');
  const publicKey = rsaPublicKey;
  const wrongPublicKey = rsaWrongPublicKey;
  const sig = jws.createSign({
    header: { alg: 'RS256' },
  });
  dataStream.pipe(sig.payload);

  process.nextTick(function () {
    privateKeyStream.pipe(sig.key);
  });

  sig.on('done', function (signature) {
    t.ok(jws.verify(signature, publicKey), 'should verify');
    t.notOk(jws.verify(signature, wrongPublicKey), 'should not verify');
    t.same(jws.decode(signature).payload, readfile('data.txt'), 'got all the data');
    t.end();
  });
});

test('Streaming sign: RSA, predefined streams', function (t) {
  const dataStream = readstream('data.txt');
  const privateKeyStream = readstream('rsa-private.pem');
  const publicKey = rsaPublicKey;
  const wrongPublicKey = rsaWrongPublicKey;
  const sig = jws.createSign({
    header: { alg: 'RS256' },
    payload: dataStream,
    privateKey: privateKeyStream
  });
  sig.on('done', function (signature) {
    t.ok(jws.verify(signature, publicKey), 'should verify');
    t.notOk(jws.verify(signature, wrongPublicKey), 'should not verify');
    t.same(jws.decode(signature).payload, readfile('data.txt'), 'got all the data');
    t.end();
  });
});

test('Streaming verify: ECDSA', function (t) {
  const dataStream = readstream('data.txt');
  const privateKeyStream = readstream('ec512-private.pem');
  const publicKeyStream = readstream('ec512-public.pem');
  const sigStream = jws.createSign({
    header: { alg: 'ES512' },
    payload: dataStream,
    privateKey: privateKeyStream
  });
  const verifier = jws.createVerify();
  sigStream.pipe(verifier.signature);
  publicKeyStream.pipe(verifier.key);
  verifier.on('done', function (valid) {
    t.ok(valid, 'should verify');
    t.end();
  });
});

test('Streaming verify: ECDSA, with invalid key', function (t) {
  const dataStream = readstream('data.txt');
  const privateKeyStream = readstream('ec512-private.pem');
  const publicKeyStream = readstream('ec512-wrong-public.pem');
  const sigStream = jws.createSign({
    header: { alg: 'ES512' },
    payload: dataStream,
    privateKey: privateKeyStream
  });
  const verifier = jws.createVerify({
    signature: sigStream,
    publicKey: publicKeyStream,
  });
  verifier.on('done', function (valid, obj) {
    t.notOk(valid, 'should not verify');
    t.end();
  });
});

test('jws.decode: not a jws signature', function (t) {
  t.same(jws.decode('some garbage string'), null);
  t.same(jws.decode('http://sub.domain.org'), null);
  t.end();
});

test('jws.decode: with a bogus header ', function (t) {
  const header = Buffer('oh hei').toString('base64');
  const payload = Buffer('sup').toString('base64');
  const sig = header + '.' + payload + '.';
  const parts = jws.decode(sig);
  t.same(parts, null);
  t.end();
});

test('jws.decode: with JWS type in header and string payload', function (t) {
  const payload = 'hi';
  const sig = jws.sign({ header: { alg: 'hs256', typ: 'JWT'}, payload: payload, secret: 'shhh' });
  t.same(jws.decode(sig).payload, payload);
  t.end();
});

test('jws.isValid', function (t) {
  const valid = jws.sign({ header: { alg: 'hs256' }, payload: 'hi', secret: 'shhh' });
  const invalid = (function(){
    const header = Buffer('oh hei').toString('base64');
    const payload = Buffer('sup').toString('base64');
    return header + '.' + payload + '.';
  })();
  t.same(jws.isValid('http://sub.domain.org'), false);
  t.same(jws.isValid(invalid), false);
  t.same(jws.isValid(valid), true);
  t.end();
});

