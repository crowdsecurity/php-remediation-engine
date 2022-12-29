# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0](https://github.com/crowdsecurity/php-remediation-engine/releases/tag/v0.3.0) - 2022-12-29
[_Compare with previous release_](https://github.com/crowdsecurity/php-remediation-engine/compare/v0.2.0...v0.3.0)

### Changed
- Update `crowdsec/capi-client` dependency to `v0.7.0`
- Update `crowdsec/lapi-client` dependency to `v0.2.0`

--- 



## [0.2.0](https://github.com/crowdsecurity/php-remediation-engine/releases/tag/v0.2.0) - 2022-12-23
[_Compare with previous release_](https://github.com/crowdsecurity/php-remediation-engine/compare/v0.1.1...v0.2.0)

### Added
- Add geolocation feature to get remediation from `Country` scoped decisions (using MaxMind databases)

--- 


## [0.1.1](https://github.com/crowdsecurity/php-remediation-engine/releases/tag/v0.1.1) - 2022-12-16
[_Compare with previous release_](https://github.com/crowdsecurity/php-remediation-engine/compare/v0.1.0...v0.1.1)

### Changed
- Update `crowdsec/capi-client` dependency to `v0.6.0`
- Add PHP `8.2` in supported versions

--- 

## [0.1.0](https://github.com/crowdsecurity/php-remediation-engine/releases/tag/v0.1.0) - 2022-12-09
[_Compare with previous release_](https://github.com/crowdsecurity/php-remediation-engine/compare/v0.0.2...v0.1.0)

### Changed
- *Breaking change*: Make methods `AbstractRemediation::storeDecisions` and `AbstractRemediation::removeDecisions` protected instead of public and modify return type (`int` to `array`)

### Added
- Add LAPI remediation feature

--- 


## [0.0.2](https://github.com/crowdsecurity/php-remediation-engine/releases/tag/v0.0.2) - 2022-12-08
[_Compare with previous release_](https://github.com/crowdsecurity/php-remediation-engine/compare/v0.0.1...v0.0.2)
### Changed
- Update `crowdsec/capi-client` dependency to allow older `symfony/config` (v4) version

--- 

## [0.0.1](https://github.com/crowdsecurity/php-remediation-engine/releases/tag/v0.0.1) - 2022-12-02
### Added
- Initial release
