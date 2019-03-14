# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import base64
import hashlib
import json
import sys
import tempfile

import click
from fido2.ctap1 import ApduError
import requests

import solo
from solo import helpers


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo key to target")
@click.option(
    "-y", "--yes", is_flag=True, help="Don't ask for confirmation before flashing"
)
@click.option(
    "--hacker", is_flag=True, default=False, help="Use this flag to flash hacker build"
)
@click.option(
    "--secure", is_flag=True, default=False, help="Use this flag to flash secure build"
)
@click.option(
    "-lfs",
    "--local-firmware-server",
    is_flag=True,
    default=False,
    hidden=True,
    help="Development option: pull firmware from http://localhost:8000",
)
@click.option(
    "--alpha",
    is_flag=True,
    default=False,
    hidden=True,
    help="Development option: use release refered to by ALPHA_VERSION",
)
def update(serial, yes, hacker, secure, local_firmware_server, alpha):
    """Update Solo key to latest firmware version."""

    # Check exactly one of --hacker/--secure is selected
    exactly_one_variant = len({hacker, secure}) == 2
    if not exactly_one_variant:
        print("Please pass exactly one of `--hacker` or `--secure` as flag!")
        print("This flag should correspond to the key you are updating.")
        sys.exit(1)

    # Determine target key
    try:
        solo_client = solo.client.find(serial)

    except solo.exceptions.NoSoloFoundError:
        print()
        print("No Solo key found!")
        print()
        print("If you are on Linux, are your udev rules up to date?")
        print("Try adding a rule line such as the following:")
        print('ATTRS{idVendor}=="0483", ATTRS{idProduct}=="a2ca", TAG+="uaccess"')
        print("For more, see https://docs.solokeys.io/solo/udev/")
        print()
        sys.exit(1)

    except solo.exceptions.NonUniqueDeviceError:
        print()
        print("Multiple Solo keys are plugged in! Please:")
        # print("  * unplug all but one key, or")
        # print("  * specify target key via `--serial SERIAL_NUMBER`")
        print("  * unplug all but one key")
        print()
        sys.exit(1)

    except Exception:
        print()
        print("Unhandled error connecting to key.")
        print("Please report via https://github.com/solokeys/solo-python/issues/")
        print()
        sys.exit(1)

    # Ensure we are in bootloader mode
    try:
        solo_client.is_solo_bootloader()
    except (RuntimeError, ApduError):
        print("Please switch key to bootloader mode:")
        print("Unplug, hold button, plug in, wait for flashing yellow light.")
        sys.exit(1)

    # Have user confirm the targetted key is secure vs hacker
    # TODO: check out automatically (currently interface is too unstable to do this.
    variant = "Solo Hacker" if hacker else "Solo Secure"
    if not yes:
        print(f"We are about to update with the latest {variant} firmware.")
        click.confirm(
            f"Please confirm that the connected Solo key is a {variant}", abort=True
        )

    # Get firmware version to use
    try:
        if alpha:
            version_file = "ALPHA_VERSION"
        else:
            version_file = "STABLE_VERSION"
        fetch_url = (
            f"https://raw.githubusercontent.com/solokeys/solo/master/{version_file}"
        )

        r = requests.get(fetch_url)
        if r.status_code != 200:
            print(
                f"Could not fetch version name from {version_file} in solokeys/solo repository!"
            )
            sys.exit(1)

        version = r.text.split()[0].strip()
        # Windows BOM haha
        # if version.encode() == b'\xef\xbf\xbd\xef\xbf\xbd1\x00.\x001\x00.\x000\x00':
        #     version = '1.1.0'
        try:
            assert version.count(".") == 2
            major, minor, patch_and_more = version.split(".")
            if "-" in patch_and_more:
                patch, pre = patch_and_more.split("-")  # noqa: F841
            else:
                patch, pre = patch_and_more, None  # noqa: F841
            major, minor, patch = map(int, (major, minor, patch))
        except Exception:
            print(f"Abnormal version format '{version}'")
            sys.exit(1)
    except Exception:
        print("Error fetching version name from solokeys/solo repository!")
        sys.exit(1)

    # Get firmware to use
    if local_firmware_server:
        base_url = "http://localhost:8000"
    else:
        base_url = f"https://github.com/solokeys/solo/releases/download/{version}"

    if hacker:
        firmware_file_github = f"firmware-hacker-{version}.hex"
    else:
        firmware_file_github = f"firmware-secure-{version}.json"
    firmware_url = f"{base_url}/{firmware_file_github}"

    extension = firmware_url.rsplit(".")[-1]

    try:
        r = requests.get(firmware_url)
        if r.status_code != 200:
            print(
                "Could not fetch official firmware build from solokeys/solo repository releases!"
            )
            print(f"URL attempted: {firmware_url}")
            sys.exit(1)
        content = r.content
        if not hacker:
            try:
                # might as well use r.json() here too
                json_content = json.loads(content.decode())
            except Exception:
                print(f"Invalid JSON content fetched from {firmware_url}!")
                sys.exit(1)

        with tempfile.NamedTemporaryFile(suffix="." + extension, delete=False) as fh:
            fh.write(r.content)
            firmware_file = fh.name
            print(f"Wrote temporary copy of {firmware_file_github} to {firmware_file}")
    except Exception:
        print("Problem fetching {firmware_url}!")
        sys.exit(1)

    # Check sha256sum
    m = hashlib.sha256()
    if hacker:
        m.update(content)
    else:
        firmware_content = base64.b64decode(
            helpers.from_websafe(json_content["firmware"]).encode()
        )
        crlf_firmware_content = b"\r\n".join(firmware_content.split(b"\n"))
        m.update(crlf_firmware_content)

    our_digest = m.hexdigest()
    digest_url = firmware_url.rsplit(".", 1)[0] + ".sha2"
    official_digest = requests.get(digest_url).text.split()[0]
    if our_digest != official_digest:
        print(
            "sha256sum of downloaded firmware file does not coincide with published sha256sum!"
        )
        print(f"sha256sum(downloaded): {our_digest}")
        print(f"sha256sum(published):  {official_digest}")
        sys.exit(1)
    print(f"sha256sums coincide: {official_digest}")

    # Actually flash it...
    solo_client.use_hid()
    try:
        # We check the key accepted signature ourselves,
        # for more pertinent error messaging.
        solo_client.set_reboot(False)
        sig = solo_client.program_file(firmware_file)
    except Exception as e:
        print("problem flashing firmware!")
        print(e)
        raise
        sys.exit(1)

    try:
        print("bootloader is verifying signature...")
        solo_client.verify_flash(sig)
        print("...pass!")
    except Exception:
        print("...error!")
        print()
        print("Your key did not accept the firmware's signature! Possible reasons:")
        print('  * Tried to flash "hacker" firmware on secure key')
        print(
            '  * Tried to flash "hacker" firmware on custom hacker key with verifying bootloader'
        )
        print()
        print(
            "Currently, your key does not work. Please run update again with correct parameters"
        )
        sys.exit(1)

    # NB: There is a remaining error case: Flashing secure firmware on hacker key
    #     will give rise to an incorrect attestation certificate.

    print()
    print(
        f"Congratulations, your {variant} was updated to the latest firmware version: {version}"
    )
