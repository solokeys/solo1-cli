# solo-python

## Installation
Running `pip install solo-python` installs both the `solo` library
and the `solotool` interface.

We require Python3.6+.

## Solo Tool
For help, run `solotool --help` after installation.

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

Code is to be formatted using [Black](https://black.readthedocs.io/) (run `make black`),
and a [CHANGELOG](CHANGELOG.md) should be kept.
