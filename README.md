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
### Nitrokey FIDO2
Automatic firmware update is not configured, since we plan to use browser-based application to do so. See https://update.nitrokey.com for details.

It is possible to run the update with this tool by hand, e.g. by executing:
```bash
# enter bootloader
nitropy fido2 util program aux enter-bootloader
nitropy fido2 util program aux bootloader-version
# download firmware by hand
wget https://github.com/Nitrokey/nitrokey-fido2-firmware/releases/download/1.1.0.nitrokey/fido2-firmware-1.1.0.nitrokey-app-signed.json
# and program it through the bootloader:
nitropy fido2 util program bootloader fido2-firmware-1.1.0.nitrokey-app-signed.json
nitropy fido2 util program aux leave-bootloader
# test key
nitropy fido2 verify
```
### Nitrokey Start

Here is brief guide for the Nitrokey Start automatic firmware download and update:
```
# install package
$ pip3 install pynitrokey

# verify installation and device connection
$ nitropy version
0.3.0
$ nitropy start list
FSIJ-1.2.15-87042524: Nitrokey Nitrokey Start (RTM.10)

# starts update process, logs saved to upgrade.log, handy in case of failure
$ nitropy start update

# does not ask for confirmation nor the default Admin PIN, handy for batch calls
$ nitropy start update -p 12345678 -y

# following will flash files from the local disk, instead of downloading them
$ nitropy start update --regnual $(FIRMWARE_DIR)/regnual.bin --gnuk ${FIRMWARE_DIR}/gnuk.bin
```


## License

Licensed similarly to upstream, under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
