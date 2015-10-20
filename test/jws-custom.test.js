/*global process*/
const test = require('tape');
const fs = require('fs');
const jws = require('..');

function readstream(path) {
  return fs.createReadStream(__dirname + '/' + path);
}

/* Custom signing algorithm that is only intended to be used for
 * these tests.
 */
const algorithm = {
  sign: function(input, key) { return Array(parseInt(key)+1).join('hi'); },
  verify: function(input, sig, key) {
    return sig === Array(parseInt(key)+1).join('hi');
  }
};

test('jws-custom.sync', function (t) {
  const opts = {
    header: {alg: 'some-custom-algorithm'},
    payload: 'hello',
    secret: 3,
    algorithm: algorithm
  };

  const sig = jws.sign(opts);
  t.same(jws.isValid(sig), true);
  t.same(jws.verify(sig, algorithm, 3), true);
  t.same(jws.verify(sig.slice(0, -1), algorithm, 3), false);

  const parts = jws.decode(sig);
  t.same(parts.header.alg, 'some-custom-algorithm');
  t.same(parts.payload, 'hello');
  t.same(parts.signature, 'hihihi');

  t.end();
});

test('jws-custom.stream', function (t) {
  const dataStream = readstream('data.txt');
  const opts = {
    header: {alg: 'some-custom-algorithm'},
    payload: dataStream,
    secret: '5',
    algorithm: algorithm
  };

  const sigStream = jws.createSign(opts);
  const verifier = jws.createVerify({algorithm: opts.algorithm, key: '5'});
  sigStream.pipe(verifier.signature);

  verifier.on('done', function(valid) {
    t.ok(valid, 'should verify');
    t.end();
  });
});
