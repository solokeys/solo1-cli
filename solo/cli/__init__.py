import sys

import click
from cryptography.hazmat.primitives import hashes
from fido2.ctap1 import ApduError
import json

import solo
import solo.operations
import solo.cli.monitor
import solo.cli.device


@click.group()
def solo_cli():
    pass


@click.command()
def version():
    """Version of python-solo library and tool."""
    print(solo.__version__)


solo_cli.add_command(version)

solo_cli.add_command(monitor.monitor)
solo_cli.add_command(device.device)


@click.command()
@click.option("--input-seed-file")
@click.argument("output_pem_file")
def genkey(input_seed_file, output_pem_file):
    """Generates key par that can be used for Solo signed firmware updates.

    \b
    * Generates NIST P256 keypair.
    * Public key must be copied into correct source location in solo bootloader
    * The private key can be used for signing updates.
    * You may optionally supply a file to seed the RNG for key generating.
    """

    vk = solo.operations.genkey(output_pem_file, input_seed_file=input_seed_file)

    print("Public key in various formats:")
    print()
    print([c for c in vk.to_string()])
    print()
    print("".join(["%02x" % c for c in vk.to_string()]))
    print()
    print('"\\x' + "\\x".join(["%02x" % c for c in vk.to_string()]) + '"')
    print()


solo_cli.add_command(genkey)


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
