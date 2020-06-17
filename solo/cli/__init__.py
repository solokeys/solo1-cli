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

import solo
import solo.operations
from solo.cli.fido2 import fido2
from solo.cli.start import start

from . import _patches  # noqa  (since otherwise "unused")

if (os.name == "posix") and os.environ.get("ALLOW_ROOT") is None:
    if os.geteuid() == 0:
        print("THIS COMMAND SHOULD NOT BE RUN AS ROOT!")
        print()
        print(
            "Please install udev rules and run `solo` as regular user (without sudo)."
        )
        print(
            "We suggest using: https://github.com/solokeys/solo/blob/master/udev/70-solokeys-access.rules"
        )
        print()
        print("For more information, see: https://docs.solokeys.io/solo/udev/")


@click.group()
def solo_cli():
    pass


solo_cli.add_command(fido2)
solo_cli.add_command(start)


@click.command()
def version():
    """Version of python-solo library and tool."""
    print(solo.__version__)


solo_cli.add_command(version)




@click.command()
def ls():
    """List Solos (in firmware or bootloader mode) and potential Solos in dfu mode."""

    fido2.commands["list"].callback()
    start.commands["list"].callback()

solo_cli.add_command(ls)

from pygments.console import colorize
print(f'*** {colorize("red", "Nitrokey tool for Nitrokey FIDO2 & Nitrokey Start")}')
