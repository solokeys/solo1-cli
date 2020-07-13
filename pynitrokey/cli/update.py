# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import os
import click
import requests
import sys
import tempfile
import json
import time

import pynitrokey
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError


@click.command()
@click.option("-s", "--serial", help="Serial number of Nitrokey key to target",
              default=None)
def update(serial):
    """Update Nitrokey key to latest firmware version."""

    #update_url = 'https://update.nitrokey.com/'
    #print('Please use {} to run the firmware update'.format(update_url))
    #return

    # Determine target key
    try:
        client = pynitrokey.client.find(serial)

    except pynitrokey.exceptions.NoSoloFoundError:
        print()
        print("No Nitrokey key found!")
        print()
        print("If you are on Linux, are your udev rules up to date?")
        print("Try adding a rule line such as the following:")
        print('ATTRS{idVendor}=="0483", ATTRS{idProduct}=="a2ca", TAG+="uaccess"')
        print("For more, see https://docs.solokeys.io/solo/udev/")
        print()
        sys.exit(1)
    except pynitrokey.exceptions.NonUniqueDeviceError:
        print()
        print("Multiple Nitrokey keys are plugged in! Please:")
        print("  * unplug all but one key")
        print()
        sys.exit(1)
    except Exception:
        print()
        print("Unhandled error connecting to key.")
        print("Please report via https://github.com/Nitrokey/pynitrokey/issues/")
        print()
        sys.exit(1)

    # determine asset url: we want the (signed) json file
    api_url = "https://api.github.com/repos/Nitrokey/nitrokey-fido2-firmware/releases/latest"
    assets = [(x["name"], x["browser_download_url"])
              for x in json.loads(requests.get(api_url).text)["assets"]]
    download_url = None
    for fn, url in assets:
        if fn.endswith(".json"):
            download_url = url
            break
    if download_url is None:
        print("Failed to determine latest release")
        return

    # download asset url
    print("Downloading latest firmware")
    tmp_dir = tempfile.gettempdir()
    fw_fn = os.path.join(tmp_dir, "fido2_firmware.json")
    with open(fw_fn, "wb") as fd:
        firmware = requests.get(download_url)
        fd.write(firmware.content)

    # Ensure we are in bootloader mode
    if client.is_solo_bootloader():
        print("Key already in bootloader mode, continuing...")
    else:
        print("Entering bootloader mode, please confirm with button on key!")
        client.enter_bootloader_or_die()
        time.sleep(0.5)

    # reconnect and actually flash it...
    try:
        client = pynitrokey.client.find(serial)
        client.use_hid()
        client.program_file(fw_fn)
    except Exception as e:
        print("ERROR - problem flashing firmware:")
        print(e)
        sys.exit(1)
    print("Congratulations, your key was updated to the latest firmware.")






