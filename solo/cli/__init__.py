# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import json

import click
import usb.core

import solo
import solo.operations
from solo.cli.key import key
from solo.cli.monitor import monitor
from solo.cli.program import program

from . import _patches  # noqa  (since otherwise "unused")
from ._checks import init_checks

init_checks()


@click.group()
def solo_cli():
    pass


solo_cli.add_command(key)
solo_cli.add_command(monitor)
solo_cli.add_command(program)


@click.command()
def version():
    """Version of python-solo library and tool."""
    print(solo.__version__)


solo_cli.add_command(version)


@click.command()
@click.option("--input-seed-file")
@click.argument("output_pem_file")
def genkey(input_seed_file, output_pem_file):
    """Generates key pair that can be used for Solo signed firmware updates.

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
@click.option("--attestation-cert", help="attestation certificate file")
@click.option(
    "--lock",
    help="Indicate to lock device from unsigned changes permanently.",
    default=False,
    is_flag=True,
)
@click.argument("input_hex_files", nargs=-1)
@click.argument("output_hex_file")
@click.option(
    "--end_page",
    help="Set APPLICATION_END_PAGE. Should be in sync with firmware settings.",
    default=20,
    type=int,
)
def mergehex(
    attestation_key, attestation_cert, lock, input_hex_files, output_hex_file, end_page
):
    """Merges hex files, and patches in the attestation key.

    \b
    If no attestation key is passed, uses default Solo Hacker one.
    Note that later hex files replace data of earlier ones, if they overlap.
    """
    solo.operations.mergehex(
        input_hex_files,
        output_hex_file,
        attestation_key=attestation_key,
        APPLICATION_END_PAGE=end_page,
        attestation_cert=attestation_cert,
        lock=lock,
    )


solo_cli.add_command(mergehex)


@click.command()
@click.option(
    "-a", "--all", is_flag=True, default=False, help="Show ST DFU devices too."
)
def ls(all):
    """List Solos (in firmware or bootloader mode) and potential Solos in dfu mode."""

    solos = solo.client.find_all()
    print(":: Solos")
    for c in solos:
        descriptor = c.dev.descriptor
        if "serial_number" in descriptor:
            print(f"{descriptor['serial_number']}: {descriptor['product_string']}")
        else:
            print(f"{descriptor['path']}: {descriptor['product_string']}")

    if all:
        print(":: Potential Solos in DFU mode")
        try:
            st_dfus = solo.dfu.find_all()
            for d in st_dfus:
                dev_raw = d.dev
                dfu_serial = dev_raw.serial_number
                print(f"{dfu_serial}")
        except usb.core.NoBackendError:
            print("No libusb available.")
            print(
                "This error is only relevant if you plan to use the ST DFU interface."
            )
            print("If you are on Windows, please install a driver:")
            print("https://github.com/libusb/libusb/wiki/Windows#driver-installation")


solo_cli.add_command(ls)
