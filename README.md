![](https://img.shields.io/pypi/l/solo1.svg?style=flat) ![](https://img.shields.io/pypi/pyversions/solo1.svg?style=flat) ![](https://img.shields.io/pypi/v/solo1.svg) ![](https://img.shields.io/pypi/wheel/solo1.svg?style=flat)

# Python tool and library for SoloKeys Solo 1

This CLI is for Solo 1, for the Solo 2 device use [solo2-cli](https://github.com/solokeys/solo2-cli).

v0.1.0 was the last to be named `solo-python`, since v0.1.1 this project is named `solo1-cli` for clarity, and available from PyPI as `solo1`.

The CLI is now called `solo1`, for the time being `solo` will also be removed, but this is deprecated.

## Getting Started
We require Python >= 3.6 and corresponding `pip3` command.

We intend to support Linux, Windows and macOS. Other platforms aren't supported by the [FIDO2 library](https://github.com/Yubico/python-fido2) we rely on.

To get started, run `pip3 install solo1`, this installs both the `solo1` library and the `solo1` command-line interface.

Possible issues:

- on Linux, ensure you have suitable udev rules in place: <https://docs.solokeys.dev/solo/udev/>
- on Windows, optionally install a libusb backend: <https://github.com/libusb/libusb/wiki/Windows#driver-installation>

For development, we suggest you run `make init` instead, which

- sets up a virtual environment
- installs development requirements such as `black`
- installs `solo1` as symlink using our packaging tool `flit`, including all runtime dependencies listed in [`pyproject.toml`](pyproject.toml)

One way to ensure the virtual environment is active is to use [direnv](https://direnv.net/).

## Solo Tool
For help, run `solo1 --help` after installation. The tool has a hierarchy of commands and subcommands.

Example:

```bash
solo1 ls  # lists all Solo keys connected to your machine
solo1 version  # outputs version of installed `solo` library and tool

solo1 key wink  # blinks the LED
solo1 key verify  # checks whether your Solo is genuine
solo1 key rng hexbytes  # outputs some random hex bytes generated on your key
solo1 key version  # outputs the version of the firmware on your key
```

## Firmware Update

Upon release of signed firmware updates in [solokeys/solo](https://github.com/solokeys/solo),
to update the firmware on your Solo to the latest version:

- update your `solo1` tool if necessary via `pip3 install --upgrade solo1`
- plug in your key, keeping the button pressed until the LED flashes yellow
- run `solo1 key update`

For possibly helpful additional information, see <https://github.com/solokeys/solo/issues/113>.

## Library Usage

The previous `solotool.py` has been refactored into a library with associated CLI tool called `solo1`.

It is still work in progress, example usage:

```python
import solo

client = solo.client.find()

client.wink()

random_bytes = client.get_rng(32)
print(random_bytes.hex())
```

Comprehensive documentation coming, for now these are the main components

- `solo.client`: connect to Solo Hacker and Solo Secure keys in firmware or bootloader mode
- `solo.dfu`: connect to Solo Hacker in dfu mode (disabled on Solo Secure keys)
- `solo.cli`: implementation of the `solo1` command line interface

## Challenge-Response

By abuse of the `hmac-secret` extension, we can generate static challenge responses,
which are scoped to a credential. A use case might be e.g. unlocking a [LUKS-encrypted](https://github.com/saravanan30erd/solokey-full-disk-encryption) drive.

**DANGER** The generated responses depend on both the key and the credential.
There is no way to extract or backup from the physical key, so if you intend to use the
"response" as a static password, make sure to store it somewhere separately, e.g. on paper.

**DANGER** Also, if you generate a new credential with the same `(host, user_id)` pair, it will likely
overwrite the old credential, and you lose the capability to generate the original responses
too.

**DANGER** This functionality has not been sufficiently debugged, please generate GitHub issues
if you detect anything.

There are two steps:

1. Generate a credential. This can be done with `solo1 key make-credential`, storing the
   (hex-encoded) generated `credential_id` for the next step.
2. Pick a challenge, and generate the associated response. This can be done with
   `solo1 key challenge-response <credential_id> <challenge>`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

Code is to be formatted and linted according to [Black](https://black.readthedocs.io/) and our [Flake8](http://flake8.pycqa.org/en/latest/) [configuration](.flake8)
Run `make check` to test compliance, run `make fix` to apply some automatic fixes.

We keep a [CHANGELOG](CHANGELOG.md).

## Releasing

For maintainers:

- adjust `solo/VERSION` file as appropriate
- add entry or entries to `CHANGELOG.md` (no need to repeat commit messages, but point out major changes
  in such a way that a user of the library has an easy entry point to follow development)
- run `make check` and/or `make fix` to ensure code consistency
- run `make build` to double check
- run `make publish` (assumes a `~/.pypirc` file with entry `[pypi]`), or `flit publish` manually
- run `make tag` to tag the release and push it
