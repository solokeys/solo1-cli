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
import re
import tempfile
from pynitrokey.cli.program import program
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError


@click.command()
@click.option("-s", "--serial", help="Serial number of Nitrokey key to target")
@click.option(
    "-y", "--yes", is_flag=True, help="Don't ask for confirmation before flashing"
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
def update(serial, yes, local_firmware_server, alpha):
    """Update Nitrokey key to latest firmware version."""

    #update_url = 'https://update.nitrokey.com/'
    #print('Please use {} to run the firmware update'.format(update_url))
    #return


    latest_release_url = "https://github.com/Nitrokey/nitrokey-fido2-firmware/releases/latest"

    web_data = requests.get(latest_release_url)

    res = re.findall(r'a href="([^"]+)"', web_data.text)
    _url = None
    for item in res:
        if "firmware" in item and "download" in item and item.endswith(".json"):
            _url = item
            break
    download_url = f"https://github.com{_url}"
    tmp_dir = tempfile.gettempdir()
    fw_fn = os.path.join(tmp_dir, "fido2_firmware.json")
    with open(fw_fn, "wb") as fd:
        firmware = requests.get(download_url)
        fd.write(firmware.content)

    print("entering bootloader mode - please confirm by touching the device's button")
    program.commands["aux"].commands["enter-bootloader"].callback(None)

    program.commands["aux"].commands["bootloader-version"].callback(None)

    print("updating Nitrokey FIDO2 using bootloader mode")
    program.commands["bootloader"].callback(None, fw_fn)

    # ensure that we are not stuck in bootloader mode...
    try:
        program.commands["aux"].commands["leave-bootloader"].callback(None)
        print("had to leave bootloader explicitly, please check firware version:")
        print("$ nitropy fido2 verify")
    except CtapError as e:
        pass


