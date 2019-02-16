import sys

import click
from cryptography.hazmat.primitives import hashes
from fido2.ctap1 import ApduError
import json

import solo
import solo.operations
import solo.cli.monitor
import solo.cli.device
import solo.cli.genkey


@click.group()
def solo_cli():
    pass


@click.command()
def version():
    print(solo.__version__)


solo_cli.add_command(version)

solo_cli.add_command(monitor.monitor)
solo_cli.add_command(device.device)
solo_cli.add_command(genkey.genkey)


@click.command()
@click.argument("verifying-key")
@click.argument("app-hex")
@click.argument("output-json")
def sign(verifying_key, app_hex, output_json):
    """Signs a firmware hex file, outputs a .json file that can be used for signed update."""

    msg = solo.operations.sign_firmware(verifying_key, app_hex)
    print("Saving signed firmware to", output_json)
    with open(output_json, "wb+") as fh:
        fh.write(json.dumps(msg).encode())


solo_cli.add_command(sign)


@click.command()
@click.option("--attestation-key", help="attestation key in hex")
@click.argument("input_hex_files", nargs=-1)
@click.argument("output_hex_file")
def mergehex(attestation_key, input_hex_files, output_hex_file):
    """Merges hex files, and patches in the attestation key.

    \b
    If no attestation key is passed, uses default Solo Hacker one.
    Note that later hex files replace data of earlier ones, if they overlap.
    """
    solo.operations.mergehex(
        input_hex_files, output_hex_file, attestation_key=attestation_key
    )


solo_cli.add_command(mergehex)
