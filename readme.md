# jws  [![Build Status](https://secure.travis-ci.org/brianloveswords/node-jws.png)](http://travis-ci.org/brianloveswords/node-jws)

[JSON Web Signatures](http://self-issued.info/docs/draft-ietf-jose-json-web-signature.html)
for node.

This was implemented against `draft-ietf-jose-json-web-signature-08`.

The following algorithms are supported:
* HMAC SHA-256 (HS256)
* RSA SHA-256 (RS256)

We yet support ECDSA yet (ES256/384/512) because OpenSSL doesn't support
it as a message digest algorithm (it only supports `ecdsa-with-sha1`)
which means we can't load it with `crypto.createSign` or
`crypto.createVerify`. Hopefully this is forthcoming.

# install

```js
$ npm install jws
```

# example

```js
const jws = require('jws');

// By default we use HMAC SHA-256
var payload = 'everybody dance NOW.';
var secret = 'supersecrettech';
var jwsObject = jws.sign(payload, secret);

jws.verify(jwsObject, secret) // === true
jws.verify(jwsObject, 'hax') // === false

// If the `secret` is a RSA key, it will figure that out and sign it appropriately.
var privateKey = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa');
var publicKey = fs.readFileSync(process.env.HOME + '/.ssh/id_rsa.pub');
var jwsObject = jws.sign(payload, privateKey);

jws.verify(jwsObject, publicKey) // === true

// By default, the header will just include the algorithm detected by
// the secret or key. If you want to add more info the the header, you
// can do so explicitly.

var jwsHmacObject = jws.sign({
  header: { alg: 'HS256', typ: 'JWT' },
  payload: payload,
  secret: secret,
});

var jwsRsaSignedObject = jws.sign({
  header: { alg: 'RS256', typ: 'Ham+Cheese' },
  payload: payload,
  key: privateKey,
});
```
