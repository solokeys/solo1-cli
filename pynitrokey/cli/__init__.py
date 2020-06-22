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

import json

import pynitrokey
import pynitrokey.operations
from pynitrokey.cli.fido2 import fido2
from pynitrokey.cli.start import start

from . import _patches  # noqa  (since otherwise "unused")

if (os.name == "posix") and os.environ.get("ALLOW_ROOT") is None:
    if os.geteuid() == 0:
        print("THIS COMMAND SHOULD NOT BE RUN AS ROOT!")
        print()
        print(
            "Please install udev rules and run `nitropy` as regular user (without sudo)."
        )
        print(
            "We suggest using: https://raw.githubusercontent.com/Nitrokey/libnitrokey/master/data/41-nitrokey.rules"
        )
        print()
        print("For more information, see: https://www.nitrokey.com/documentation/installation#p:nitrokey-fido2&os:linux")


@click.group()
def nitropy():
    pass


nitropy.add_command(fido2)
nitropy.add_command(start)


@click.command()
def version():
    """Version of pynitrokey library and tool."""
    print(pynitrokey.__version__)


nitropy.add_command(version)




@click.command()
def ls():
    """List Nitrokey keys (in firmware or bootloader mode)"""

    fido2.commands["list"].callback()
    start.commands["list"].callback()

nitropy.add_command(ls)

from pygments.console import colorize
print(f'*** {colorize("red", "Nitrokey tool for Nitrokey FIDO2 & Nitrokey Start")}')
