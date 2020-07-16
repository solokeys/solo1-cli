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

from pynitrokey.helpers import local_print



@click.command()
@click.option("-s", "--serial", help="Serial number of Nitrokey key to target",
              default=None)
@click.option('-y', 'yes', default=False, is_flag=True, help='agree to everything')
def update(serial, yes):
    """Update Nitrokey key to latest firmware version."""

    #update_url = 'https://update.nitrokey.com/'
    #print('Please use {} to run the firmware update'.format(update_url))
    #return

    # Determine target key
    try:
        client = pynitrokey.client.find(serial)

    except pynitrokey.exceptions.NoSoloFoundError as e:
        print()
        local_print("No Nitrokey key found!", exc=e)
        print()
        local_print("If you are on Linux, are your udev rules up to date?")
        local_print("For more, see https://www.nitrokey.com/documentation/installation#os:linux")
        print()
        sys.exit(1)
    except pynitrokey.exceptions.NonUniqueDeviceError as e:
        print()
        local_print("Multiple Nitrokey keys are plugged in!", exc=e)
        local_print("Please unplug all but one key")
        print()
        sys.exit(1)
    except Exception as e:
        print()
        local_print("Unhandled error connecting to key.", exc=e)
        local_print("Please report via https://github.com/Nitrokey/pynitrokey/issues/")
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
        local_print("Failed to determine latest release")
        sys.exit(1)

    # download asset url
    local_print("Downloading latest firmware")
    tmp_dir = tempfile.gettempdir()
    fw_fn = os.path.join(tmp_dir, "fido2_firmware.json")
    with open(fw_fn, "wb") as fd:
        firmware = requests.get(download_url)
        fd.write(firmware.content)

    # ask for permission
    if not yes:
        local_print('This will update your Nitrokey FIDO2...')
        answer = input('Do you want to continue? [yes/no]: ')
        local_print('Entered: "{}"'.format(answer))
        if answer != 'yes':
            local_print('Device is not modified. Exiting.')
            sys.exit(1)

    # Ensure we are in bootloader mode
    if client.is_solo_bootloader():
        local_print("Key already in bootloader mode, continuing...")
    else:
        try:
            local_print("Entering bootloader mode, please confirm with button on key!")
            client.enter_bootloader_or_die()
            time.sleep(0.5)
        except Exception as e:
            local_print("ERROR - problem switching to bootloader mode:", exc=e)
            sys.exit(1)

    # reconnect and actually flash it...
    try:
        client = pynitrokey.client.find(serial)
        client.use_hid()
        client.program_file(fw_fn)
    except Exception as e:
        local_print("ERROR - problem flashing firmware:", exc=e)
        sys.exit(1)
    local_print("Congratulations, your key was updated to the latest firmware.")






