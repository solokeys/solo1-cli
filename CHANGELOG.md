# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
