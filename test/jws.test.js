/*global process*/
const Buffer = require('safe-buffer').Buffer;
const fs = require('fs');
const test = require('tape');
const jws = require('..');

const NODE_VERSION = require('semver').clean(process.version);
const SUPPORTS_ENCRYPTED_KEYS = require('semver').gte(NODE_VERSION, '0.11.8');

function readfile(path) {
  return fs.readFileSync(__dirname + '/' + path).toString();
}

function readstream(path) {
  return fs.createReadStream(__dirname + '/' + path);
}

const rsaPrivateKey = readfile('rsa-private.pem');
const rsaPrivateKeyEncrypted = readfile('rsa-private-encrypted.pem');
const encryptedPassphrase = readfile('encrypted-key-passphrase');
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

const payloadString = 'oh ćhey José!: ¬˚∆ƒå¬ß…©…åˆø˙ˆø´∆¬˚µ…˚¬˜øå…ˆßøˆƒ˜¬';
const payload = {
  name: payloadString,
  value: ['one', 2, 3]
};

BITS.forEach(function (bits) {
  test('HMAC using SHA-'+bits+' hash algorithm', function (t) {
    const alg = 'HS'+bits;
    const header = { alg: alg, typ: 'JWT' };
    const secret = 'sup';
    jws.sign({
      header: header,
      payload: payload,
      secret: secret,
      encoding: 'utf8',
    }).then(function (jwsObj) {
      return jws.verify(jwsObj, alg, secret).then(function (res) {
        t.ok(res, 'should verify');
        return jws.verify(jwsObj, alg, 'something else');
      }).then(function (res) {
        const parts = jws.decode(jwsObj);
        t.notOk(res, 'should not verify with non-matching secret');
        t.same(parts.payload, payload, 'should match payload');
        t.same(parts.header, header, 'should match header');
        t.end();
      }).catch(function (e) {
        t.end(e);
      });
    });
  });
});

BITS.forEach(function (bits) {
  test('RSASSA using SHA-'+bits+' hash algorithm', function (t) {
    const alg = 'RS'+bits;
    const header = { alg: alg };
    const privateKey = rsaPrivateKey;
    const publicKey = rsaPublicKey;
    const wrongPublicKey = rsaWrongPublicKey;
    jws.sign({
      header: header,
      payload: payload,
      privateKey: privateKey
    }).then(function (jwsObj) {
      return jws.verify(jwsObj, alg, publicKey).then(function (res) {
        t.ok(res, 'should verify');
        return jws.verify(jwsObj, alg, wrongPublicKey);
      }).then(function (res) {
        t.notOk(res, 'should not verify with non-matching public key');
        return jws.verify(jwsObj, 'HS' + bits, publicKey);
      }).then(function (res) {
        t.notOk(res, 'should not verify with non-matching algorithm');
      }).then(function () {
        const parts = jws.decode(jwsObj, { json: true });
        t.same(parts.payload, payload, 'should match payload');
        t.same(parts.header, header, 'should match header');
        t.end();
      });
    }).catch(function (e) {
      t.end(e);
    });
  });
});

BITS.forEach(function (bits) {
  const curve = CURVES[bits];
  test('ECDSA using P-'+curve+' curve and SHA-'+bits+' hash algorithm', function (t) {
    const alg = 'ES'+bits;
    const header = { alg: alg };
    const privateKey = ecdsaPrivateKey[bits];
    const publicKey = ecdsaPublicKey[bits];
    const wrongPublicKey = ecdsaWrongPublicKey[bits];
    jws.sign({
      header: header,
      payload: payloadString,
      privateKey: privateKey
    }).then(function (jwsObj) {
      return jws.verify(jwsObj, alg, publicKey).then(function (res) {
        t.ok(res, 'should verify');
        return jws.verify(jwsObj, alg, wrongPublicKey);
      }).then(function (res) {
        t.notOk(res, 'should not verify with non-matching public key');
        return jws.verify(jwsObj, 'HS' + bits, publicKey);
      }).then(function (res) {
        const parts = jws.decode(jwsObj);
        t.notOk(res, 'should not verify with non-matching algorithm');
        t.same(parts.payload, payloadString, 'should match payload');
        t.same(parts.header, header, 'should match header');
        t.end();
      });
    }).catch(function (e) {
      t.end(e);
    });
  });
});

test('No digital signature or MAC value included', function (t) {
  const alg = 'none';
  const header = { alg: alg };
  const payload = 'oh hey José!';
  jws.sign({
    header: header,
    payload: payload,
  }).then(function (jwsObj) {
    return jws.verify(jwsObj, alg).then(function (res) {
      t.ok(res, 'should verify');
      return jws.verify(jwsObj, alg, 'anything');
    }).then(function (res) {
      t.ok(res, 'should still verify');
      return jws.verify(jwsObj, 'HS256', 'anything');
    }).then(function (res) {
      const parts = jws.decode(jwsObj);
      t.notOk(res, 'should not verify with non-matching algorithm');
      t.same(parts.payload, payload, 'should match payload');
      t.same(parts.header, header, 'should match header');
      t.end();
    });
  }).catch(function (e) {
    t.end(e);
  });
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
    jws.verify(signature, 'HS256', secret).then(function (res) {
      t.ok(res, 'should verify');
      t.end();
    }).catch(function (e) {
      t.end(e);
    });
  });
  sig.on('error', function (error) {
    t.end(error);
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
    jws.verify(signature, 'RS256', publicKey).then(function (res) {
      t.ok(res, 'should verify');
      return jws.verify(signature, 'RS256', wrongPublicKey);
    }).then(function (res) {
      t.notOk(res, 'should not verify');
      t.same(jws.decode(signature).payload, readfile('data.txt'), 'got all the data');
      t.end();
    }).catch(function (e) {
      t.end(e);
    });
  });

  sig.on('error', function (error) {
    t.end(error);
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
    jws.verify(signature, 'RS256', publicKey).then(function (res) {
      t.ok(res, 'should verify');
      return jws.verify(signature, 'RS256', wrongPublicKey);
    }).then(function (res) {
      t.notOk(res, 'should not verify');
      t.same(jws.decode(signature).payload, readfile('data.txt'), 'got all the data');
      t.end();
    }).catch(function (e) {
      t.end(e);
    });
  });
  sig.on('error', function (error) {
    t.end(error);
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
  const verifier = jws.createVerify({algorithm: 'ES512'});
  sigStream.pipe(verifier.signature);
  publicKeyStream.pipe(verifier.key);
  verifier.on('done', function (valid) {
    t.ok(valid, 'should verify');
    t.end();
  });
  verifier.on('error', function (error) {
    t.end(error);
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
    algorithm: 'ES512',
    signature: sigStream,
    publicKey: publicKeyStream,
  });
  verifier.on('done', function (valid) {
    t.notOk(valid, 'should not verify');
    t.end();
  });
  verifier.on('error', function (error) {
    t.end(error);
  });
});

test('Streaming verify: errors during verify should emit as "error"', function (t) {
  const verifierShouldError = jws.createVerify({
    algorithm: 'ES512',
    signature: 'a.b.c', // the short/invalid length signature will make jwa throw
    publicKey: 'invalid-key-will-make-crypto-throw'
  });

  verifierShouldError.on('done', function () {
    t.fail();
    t.end();
  });
  verifierShouldError.on('error', function () {
    t.end();
  });
});

if (SUPPORTS_ENCRYPTED_KEYS) {
  test('Signing: should accept an encrypted key', function (t) {
    const alg = 'RS256';
    jws.sign({
      header: { alg: alg },
      payload: 'verifyme',
      privateKey: {
        key: rsaPrivateKeyEncrypted,
        passphrase: encryptedPassphrase
      }
    }).then(function (signature) {
      t.ok(jws.verify(signature, 'RS256', rsaPublicKey));
      t.end();
    }).catch(function (e) {
      t.end(e);
    });
  });

  test('Streaming sign: should accept an encrypted key', function (t) {
    const alg = 'RS256';
    const signer = jws.createSign({
      header: { alg: alg },
      payload: 'verifyme',
      privateKey: {
        key: rsaPrivateKeyEncrypted,
        passphrase: encryptedPassphrase
      }
    });
    const verifier = jws.createVerify({
      algorithm: alg,
      signature: signer,
      publicKey: rsaPublicKey
    });
    verifier.on('done', function (verified) {
      t.ok(verified);
      t.end();
    });
    verifier.on('error', function (error) {
      t.end(error);
    });
  });
}

test('jws.decode: not a jws signature', function (t) {
  t.same(jws.decode('some garbage string'), null);
  t.same(jws.decode('http://sub.domain.org'), null);
  t.end();
});

test('jws.decode: with a bogus header ', function (t) {
  const header = Buffer.from('oh hei José!').toString('base64');
  const payload = Buffer.from('sup').toString('base64');
  const sig = header + '.' + payload + '.';
  const parts = jws.decode(sig);
  t.same(parts, null);
  t.end();
});

test('jws.decode: with invalid json in body', function (t) {
  const header = Buffer.from('{"alg":"HS256","typ":"JWT"}').toString('base64');
  const payload = Buffer.from('sup').toString('base64');
  const sig = header + '.' + payload + '.';
  t.throws(function () {
    jws.decode(sig);
  });
  t.end();
});

test('jws.verify: missing or invalid algorithm', function (t) {
  const header = Buffer.from('{"something":"not an algo"}').toString('base64');
  const payload = Buffer.from('sup').toString('base64');
  const sig = header + '.' + payload + '.';
  jws.verify(sig).then(function () {
    // should have rejected before this
    t.fail();
  }).catch(function (e) {
    t.same(e.code, 'MISSING_ALGORITHM');
  }).then(function () {
    return jws.verify(sig, 'whatever').then(function () {
      // should have rejected before this
      t.fail();
    });
  }).catch(function (e) {
    t.ok(e.message.match('"whatever" is not a valid algorithm.'));
    t.end();
  }).catch(function (e) {
    t.end(e);
  });
});


test('jws.isValid', function (t) {
  jws.sign({ header: { alg: 'HS256' }, payload: 'hi', secret: 'shhh' }).then(function (valid) {
    const invalid = (function () {
      const header = Buffer.from('oh hei José!').toString('base64');
      const payload = Buffer.from('sup').toString('base64');
      return header + '.' + payload + '.';
    })();
    t.same(jws.isValid('http://sub.domain.org'), false);
    t.same(jws.isValid(invalid), false);
    t.same(jws.isValid(valid), true);
    t.end();
  }).catch(function (e) {
    t.end(e);
  });
});

test('custom jwa', function (t) {
  var verifyCalls = [];
  var signCalls = [];
  function jwa(alg) {
    if (alg === 'CUSTOM') {
      return {
        verify: function (payload, signature, secret) {
          verifyCalls.push([payload, signature, secret]);
          if (secret === 'shhh') {
            return signature === 'SIGNED';
          }
          return false;
        },
        sign: function (payload, secret) {
          signCalls.push([payload, secret]);
          if (secret === 'shhh') {
            return 'SIGNED';
          }
          throw new Error('unable to sign');
        },
      };
    }
  }
  jws.sign({ header: { alg: 'CUSTOM' }, payload: 'hi', secret: 'shhh', jwa: jwa }).then(function (signature) {
    t.same(signCalls.length, 1);
    t.same(signature, 'eyJhbGciOiJDVVNUT00ifQ.aGk.SIGNED');
    return jws.sign({ header: { alg: 'CUSTOM' }, payload: 'hi', secret: 'bad', jwa: jwa }).then(function () {
      t.fail();
    }).catch(function (e) {
      t.same(signCalls.length, 2);
      t.same(e.message, 'unable to sign');
    });
  }).then(function () {
    return jws.verify('eyJhbGciOiJDVVNUT00ifQ.aGk.SIGNED', 'CUSTOM', 'shhh', { jwa: jwa });
  }).then(function (valid) {
    t.same(verifyCalls.length, 1);
    t.ok(valid);
    return jws.verify('eyJhbGciOiJDVVNUT00ifQ.aGk.invalid', 'CUSTOM', 'shhh', { jwa: jwa });
  }).then(function (valid) {
    t.same(verifyCalls.length, 2);
    t.notOk(valid);
    t.end();
  }).catch(function (e) {
    t.end(e);
  });
});
