# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.1.0](https://github.com/crowdsecurity/php-remediation-engine/releases/tag/v0.1.0) - 2022-12-??
[_Compare with previous release_](https://github.com/crowdsecurity/php-remediation-engine/compare/v0.0.2...v0.1.0)

### Changed
- *Breaking change*: Make methods `AbstractRemediation::storeDecisions` and `AbstractRemediation::removeDecisions` protected instead of public and modify return type (`int` to `array`)


### Added
- Add Lapi Remeditation feature

--- 


## [0.0.2](https://github.com/crowdsecurity/php-remediation-engine/releases/tag/v0.0.2) - 2022-12-08
[_Compare with previous release_](https://github.com/crowdsecurity/php-remediation-engine/compare/v0.0.1...v0.0.2)
### Changed
- Update `crowdsec/capi-client` dependency to allow older `symfony/config` (v4) version

--- 

## [0.0.1](https://github.com/crowdsecurity/php-remediation-engine/releases/tag/v0.0.1) - 2022-12-02
### Added
- Initial release
