# Change Log
All notable changes to this project will be documented in this file.

## [unreleased]
### Changed
- **BREAKING**: `jws.verify` and `jws.sign` now return a `Promise`.

### Added
- `jws.verify` and `jws.sign` now accepts a `jwa` callback which can be used to resolve an object
  with `sign` and `verify` functions for the key/secret provided; these functions may return a
  `Promise`.

### Removed
- Support for Node v0.10 has been removed due to lack of Promise support.

## [4.0.0] - 2019-12-17
### Changed
- **BREAKING**: `jwa` was updated and now matches algorithm names
  case-sensitively. Should a jws header have an alg such as "es256"
  instead of the IANA registered "ES256" it will now throw.


## [3.0.0] - 2015-04-08
### Changed
- **BREAKING**: `jwt.verify` now requires an `algorithm` parameter, and
  `jws.createVerify` requires an `algorithm` option. The `"alg"` field
  signature headers is ignored. This mitigates a critical security flaw
  in the library which would allow an attacker to generate signatures with
  arbitrary contents that would be accepted by `jwt.verify`. See
  https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
  for details.

## [2.0.0] - 2015-01-30
### Changed
- **BREAKING**: Default payload encoding changed from `binary` to
  `utf8`. `utf8` is a more sensible default than `binary` because
  many payloads, as far as I can tell, will contain user-facing
  strings that could be in any language. (<code>[6b6de48]</code>)

- Code reorganization, thanks [@fearphage]! (<code>[7880050]</code>)

### Added
- Option in all relevant methods for `encoding`. For those few users
  that might be depending on a `binary` encoding of the messages, this
  is for them. (<code>[6b6de48]</code>)

[unreleased]: https://github.com/brianloveswords/node-jws/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/brianloveswords/node-jws/compare/v3.2.2...v4.0.0
[3.0.0]: https://github.com/brianloveswords/node-jws/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/brianloveswords/node-jws/compare/v1.0.1...v2.0.0

[7880050]: https://github.com/brianloveswords/node-jws/commit/7880050
[6b6de48]: https://github.com/brianloveswords/node-jws/commit/6b6de48

[@fearphage]: https://github.com/fearphage
