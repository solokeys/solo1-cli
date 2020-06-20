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
import time

import click
import requests
import pynitrokey
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from pynitrokey import helpers


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

    update_url = 'https://update.nitrokey.com/'
    print('Please use {} to run the firmware update'.format(update_url))
    return

