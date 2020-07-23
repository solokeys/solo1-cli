# pynitrokey

A command line interface for the Nitrokey FIDO2 and Nitrokey Start.

## Current state
Project is in alpha stage, not meant yet to be used by end-users (not everything was tested), although almost all features should work out-of-the-box. The strings referring to the device were not changed yet as well.

Differences:
- handle `status` command for displaying touch button status (2.0.0 firmware and later);
- firmware signing adjusted for Nitrokey FIDO2 bootloader
- monitor command with timestamps
- disabled automatic update (however manual update works)

## Installation

### Linux, Unix

```
sudo apt install python3-pip
pip3 install --user pynitrokey
```

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
### Nitrokey FIDO2 (Windows)
For Windows there is an installer for **pynitrokey**, just follow these steps to 
update your Nitrokey FIDO2 key:

* Download the latest `.msi` installer from the [releases](https://github.com/Nitrokey/pynitrokey/releases/)
* Double-click the installer and click through (`Next` and `Finish`)
* Open the windows start menu and type `cmd` and press enter
* Inside the terminal window type: `nitropy fido2 update` and follow the instructions

Your Nitrokey FIDO2 is now updated to the latest firmware.

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

## Nitrokey Start: Switching ID

```
nitropy start set-identity [0,1,2]
```

Where 0, 1 and 2 are the available IDs.

## License

Licensed similarly to upstream, under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
