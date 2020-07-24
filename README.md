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

```bash
sudo apt install python3-pip
pip3 install --user pynitrokey
```

### Windows

1. Download the latest `.msi` installer from the [releases](https://github.com/Nitrokey/pynitrokey/releases/)
1. Double-click the installer and click through (`Next` and `Finish`)
1. Open the windows start menu and type `cmd` and press enter

## Nitrokey FIDO2
### Firmware Update
Automatic firmware update is recommended via https://update.nitrokey.com. Alternatively, it is also possible to update the Nitrokey FIDO2 using:
```bash
nitropy fido2 update
```

Your Nitrokey FIDO2 is now updated to the latest firmware.

## Nitrokey Start
### Firmware Update

Verify device connection

```bash
nitropy start list
FSIJ-1.2.15-87042524: Nitrokey Nitrokey Start (RTM.10)
```
Start update process, logs saved to upgrade.log, handy in case of failure

```bash
nitropy start update
```

Does not ask for confirmation nor the default Admin PIN, handy for batch calls
```
nitropy start update -p 12345678 -y
```

Following will flash files from the local disk, instead of downloading them
```
nitropy start update --regnual $(FIRMWARE_DIR)/regnual.bin --gnuk ${FIRMWARE_DIR}/gnuk.bin
```

### Switching ID

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
