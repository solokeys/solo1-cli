import sys

import click
from cryptography.hazmat.primitives import hashes
from fido2.ctap1 import ApduError

import solo
import solo.cli.monitor
import solo.cli.device


@click.group()
def solo_cli():
    pass


@click.command()
def version():
    print(solo.__version__)

solo_cli.add_command(version)

solo_cli.add_command(monitor.monitor)
solo_cli.add_command(device.device)
