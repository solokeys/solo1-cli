# -*- coding: utf-8 -*-
#
# Copyright 2020 Nitrokey Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import sys
from time import sleep, time
from subprocess import check_output

import click

from pynitrokey.start.gnuk_token import get_gnuk_device
from pynitrokey.start.usb_strings import get_devices as get_devices_strings

from pynitrokey.start.upgrade_by_passwd import validate_gnuk, validate_regnual, logger, \
    start_update, DEFAULT_WAIT_FOR_REENUMERATION, DEFAULT_PW3, IS_LINUX
from pynitrokey.start.threaded_log import ThreadLog

from usb.core import USBError


# https://pocoo-click.readthedocs.io/en/latest/commands/#nested-handling-and-contexts
@click.group()
def start():
    """Interact with 'Nitrokey Start' keys, see subcommands."""
    pass


@click.command()
def list():
    """list connected devices"""
    print(":: 'Nitrokey Start' keys:")
    for dct in get_devices_strings():
        print(f"{dct['Serial']}: {dct['Vendor']} {dct['Product']} ({dct['Revision']})")


@click.command()
@click.argument("identity")
def set_identity(identity):
    """set given identity (one of: 0, 1, 2)"""
    if not identity.isdigit():
        print("identity number must be a digit")
        sys.exit(1)
    identity = int(identity)
    if identity < 0 or identity > 2:
        print("identity must be 0, 1 or 2")
        sys.exit(1)
    print(f"Trying to set identity to {identity}")
    for x in range(3):
        try:
            gnuk = get_gnuk_device()
            gnuk.cmd_select_openpgp()
            try:
                gnuk.cmd_set_identity(identity)
            except USBError:
                print("device has reset, and should now have the new identity")
                sys.exit(0)

        except ValueError as e:
            if 'No ICC present' in str(e):
                print("Could not connect to device, trying to close scdaemon")
                result = check_output(["gpg-connect-agent",
                                       "SCD KILLSCD", "SCD BYE",
                                       "/bye"])  # gpgconf --kill all might be better?
                sleep(3)
            else:
                print('*** Found error: {}'.format(str(e)))


@click.command()
@click.option(
    '--regnual', default=None, callback=validate_regnual, help='path to regnual binary'
)
@click.option(
    '--gnuk', default=None, callback=validate_gnuk, help='path to gnuk binary'
)
@click.option('-f', 'default_password', is_flag=True, default=False,
  help=f'use default Admin PIN: {DEFAULT_PW3}')
@click.option('-p', 'password', help='use provided Admin PIN')
@click.option('-e', 'wait_e', default=DEFAULT_WAIT_FOR_REENUMERATION, type=int,
    help='time to wait for device to enumerate, after regnual was executed on device')
@click.option('-k', 'keyno', default=0, type=int, help='selected key index')
@click.option('-v', 'verbose', default=0, type=int, help='verbosity level')
@click.option('-y', 'yes', default=False, is_flag=True, help='agree to everything')
@click.option('-b', 'skip_bootloader', default=False, is_flag=True,
    help='Skip bootloader upload (e.g. when done so already)')
@click.option(
    '--green-led', is_flag=True, default=False,
    help='Use firmware for early "Nitrokey Start" key hardware revisions'
)
def update(regnual, gnuk, default_password, password, wait_e, keyno, verbose, yes,
           skip_bootloader, green_led):
    """update device's firmware"""

    args = (regnual, gnuk, default_password, password, wait_e, keyno, verbose, yes,
           skip_bootloader, green_led)

    if green_led and (regnual is None or gnuk is None):
        print("You selected the --green-led option, please provide '--regnual' and "
              "'--gnuk' in addition to proceed. ")
        print("use on from: https://github.com/Nitrokey/nitrokey-start-firmware)")
        sys.exit(1)

    if IS_LINUX:
        with ThreadLog(logger.getChild('dmesg'), 'dmesg -w'):
            start_update(*args)
    else:
        start_update(*args)


start.add_command(list)
start.add_command(set_identity)
start.add_command(update)
# start.add_command(rng)
# start.add_command(reboot)
# rng.add_command(hexbytes)
# rng.add_command(raw)
# rng.add_command(feedkernel)
# start.add_command(make_credential)
# start.add_command(challenge_response)
# start.add_command(reset)
# start.add_command(status)
# start.add_command(update)
# start.add_command(probe)
# # key.add_command(sha256sum)
# # key.add_command(sha512sum)
# start.add_command(version)
# start.add_command(verify)
# start.add_command(wink)
