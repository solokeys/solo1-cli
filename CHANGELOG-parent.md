# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.18] - 2019-10-29
### Added
### Changed
- When signing, signatures were incorrectly annotated with `2.3.0` version.  updated to `2.5.3`.

## [0.0.17] - 2019-10-28
### Added
### Changed
- remove `--hacker` and `--secure` options when auto-updating.
- pull `firmware-*.json` instead of choosing between hacker and secure

## [0.0.16] - 2019-10-28
### Added
- option to specify attestation certificate with attestation key
- mergehex operation adds in attestation certificate
- mergehex operation adds in lock status with `--lock` flag

### Changed
- attestation key requires associate attestation cert
- sign operation adds 2 signatures for 2 different versions of solo bootloader
- solo version attempts to uses HID version command to additionally see lock status of key.

## [0.0.15] - 2019-08-30
### Added
- `solo.hmac_secret.make_credential` method
- separate `solo key make-credential` CLI target

### Changed
- remove credential generation from `solo.hmac_secret.simple_secret`
- demand `credential_id` in `solo key challenge-response`

## [0.0.14] - 2019-08-30
### Added
- challenge-response via `hmac-secret`

## [0.0.13] - 2019-08-19
### Changed
- implement passing PIN to `solo key verify`

## [0.0.12] - 2019-08-08
### Changed
- update fido2 to 0.7.0

## [0.0.11] - 2019-05-27
### Changed
- adjust to and pin fido2 0.6.0 dependency (@conorpp)
- only warn if run as sudo

## [0.0.10] - 2019-03-18
### Added
- solo client improvements
- experimental interface to feed kernel entropy from key:
`sudo ALLOW_ROOT= /path/to/solo key rng feedkernel`

## [0.0.9] - 2019-03-18
### Added
- enforce `solo` command does not run as root

## [0.0.8] - 2019-03-18
### Added
- `solo key probe` interface
### Changed
- fixes to set options bytes to leave DFU mode

## [0.0.7] - 2019-03-08
### Changed
- Exit properly on boot to bootloader failure
- `--alpha` flag for `update`

## [0.0.6] - 2019-02-27
### Changed
- Fix bootloader-version command (@Thor77)
- Reboot to bootloader in `program` if necessary
### Added
- yes flag for `update`

## [0.0.6a3] - 2019-02-20
### Changed
- Typo

## [0.0.6a2] - 2019-02-20
### Added
- Monkey-patch to communicate via UDP with software key
- Flag `--udp` to use it for certain `solo key` commands

## [0.0.6a1] - 2019-02-19
### Added
- Serial number support

## [0.0.5] - 2019-02-18
### Changed
- Initial feedback from https://github.com/solokeys/solo/issues/113

## [0.0.4] - 2019-02-18
### Changed
- Enforce passing exactly one of `--hacker|--secure` in `solo key update`

## [0.0.3] - 2019-02-18
### Changed
- Bugfix in `solo.dfu`
- Minor improvements

## [0.0.2] - 2019-02-18
### Changed
- Fix broken `solo program dfu` command
- Remove `solotool` script installation
- Add Python version classifiers

## [0.0.1] - 2019-02-17
### Added
- Implement `solo key update [--hacker]`

## [0.0.1a8] - 2019-02-17
### Added
- Forgot to add some files in last release
- Add client/dfu find\_all methods
- Add `solo ls` command

## [0.0.1a7] - 2019-02-16
### Added
- More implementation of `solo program aux` (mode changes)
- Implement `solo program bootloader`.
- More comments

## [0.0.1a6] - 2019-02-16
### Changed
- Implements part of `solo program dfu` and `solo program aux`
- Adds Conor's change allowing to pass in raw devices to DFU+SoloClient

## [0.0.1a5] - 2019-02-16
### Changed
- Unwrap genkey from CLI to operations

## [0.0.1a4] - 2019-02-16
### Added
- Everything moved out of solotool, except programming chunk

## [0.0.1a3] - 2019-02-16
### Added
- Start redo of CLI using click

## [0.0.1a2] - 2019-02-15
### Changed
- Bugfixes related to refactor

## [0.0.1a1] - 2019-02-15
### Changed
- Start to split out commands, helpers and client

## [0.0.1a0] - 2019-02-15
### Added
- Initial import of `solotool.py` script from [solo](https://github.com/solokeys/solo)
