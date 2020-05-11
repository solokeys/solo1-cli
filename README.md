# Nitro-python

A command line interface for the Nitrokey FIDO2. Work in progress.

This is a fork of https://github.com/solokeys/solo-python (see [README-parent.md](README-parent.md)).

## Current state
Project is in alpha stage, not meant yet to be used by end-users (not everything was tested), although almost all features should work out-of-the-box. The strings referring to the device were not changed yet as well.

Differences:
- handle `status` command for displaying touch button status (2.0.0 firmware and later);
- firmware signing adjusted for Nitrokey FIDO2 bootloader
- monitor command with timestamps
- disabled automatic update (however manual update works)

## Firmware update (manual)
Automatic firmware update is not configured, since we plan to use browser-based application to do so. See https://update.nitrokey.com for details.

It is possible to run the update with this tool by hand, e.g. by executing:
```bash
# enter bootloader
nitrokey program aux enter-bootloader
nitrokey program aux bootloader-version
# download firmware by hand
wget https://github.com/Nitrokey/nitrokey-fido2-firmware/releases/download/1.1.0.nitrokey/fido2-firmware-1.1.0.nitrokey-app-signed.json
# and program it through the bootloader:
solo program bootloader fido2-firmware-1.1.0.nitrokey-app-signed.json
nitrokey program aux leave-bootloader
# test key
nitrokey key verify
```


## License

Licensed similarly to upstream, under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
