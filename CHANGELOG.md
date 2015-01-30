# Change Log
All notable changes to this project will be documented in this file.

## [2.0.0] - 2015-01-30
### Changed
- **BREAKING**: Default payload encoding changed from `binary` to
  `utf8`. `utf8` is a is a more sensible default than `binary` because
  many payloads, as far as I can tell, will contain user-facing
  strings that could be in any language. (<code>[6b6de48]</code>)

- Code reorganization, thanks [@fearphage]! (<code>[7880050]</code>)

### Added
- Option in all relevant methods for `encoding`. For those few users
  that might be depending on a `binary` encoding of the messages, this
  is for them. (<code>[6b6de48]</code>)

[unreleased]: https://github.com/brianloveswords/node-jws/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/olivierlacan/keep-a-changelog/compare/v2.0.0...v1.0.1

[7880050]: https://github.com/brianloveswords/node-jws/commit/7880050
[6b6de48]: https://github.com/brianloveswords/node-jws/commit/6b6de48

[@fearphage]: https://github.com/fearphage
