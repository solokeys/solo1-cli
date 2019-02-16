# Python tool and library for SoloKeys

## Getting Started
We require Python >= 3.6, and intend to support Linux, Windows and macOS.

To get started, run `pip install solo-python`, this installs the `solo` library and the `solotool` interface.

For development, we suggest you run `make init`, which

- sets up a virtual environment
- installs development requirements such as `black`
- installs `solo` with `flit` as symlink, including all runtime dependencies listed in `pyproject.toml`

One way to ensure the virtual environment is active is to use [direnv](https://direnv.net/).

## Solo Tool
For help, run `solotool --help` after installation.

Example:

```bash
solotool solo --wink
```

## Library Usage
Refactoring into a library is work in progress; current example:
```python
import solo

client = solo.client.SoloClient()
client.find_device()

client.wink()

random_bytes = client.get_rng(32)
print(random_bytes.hex())
```

## License
Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing
Any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

Code is to be formatted using [Black](https://black.readthedocs.io/) (run `make black`), and a [CHANGELOG](CHANGELOG.md) shall be kept.
