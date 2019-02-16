# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import sys

import click
from cryptography.hazmat.primitives import hashes
from fido2.ctap1 import ApduError

import solo


# https://pocoo-click.readthedocs.io/en/latest/commands/#nested-handling-and-contexts
@click.group()
def key():
    """Interact with Solo keys, see subcommands."""
    pass


@click.group()
def rng():
    """Access TRNG on key, see subcommands."""
    pass


@click.command()
@click.option("--count", default=8, help="How many bytes to generate (defaults to 8)")
def hexbytes(count):
    """Output COUNT number of random bytes, hex-encoded."""
    if not 0 <= count <= 255:
        print(f"Number of bytes must be between 0 and 255, you passed {count}")
        sys.exit(1)

    print(solo.client.find().get_rng(count).hex())


@click.command()
def raw():
    """Output raw entropy endlessly."""
    p = solo.client.find()
    while True:
        r = p.get_rng(255)
        sys.stdout.buffer.write(r)


@click.command()
def reset():
    """Reset key - wipes all credentials!!!"""
    if click.confirm(
        "Warning: Your credentials will be lost!!! Do you wish to continue?"
    ):
        print("Press the button to confirm -- again, your credentials will be lost!!!")
        solo.client.find().reset()
        click.echo("....aaaand they're gone")


@click.command()
def verify():
    """Verify key is valid Solo Secure or Solo Hacker."""
    # Any longer and this needs to go in a submodule
    cert = solo.client.find().make_credential()

    solo_fingerprint = b"r\xd5\x831&\xac\xfc\xe9\xa8\xe8&`\x18\xe6AI4\xc8\xbeJ\xb8h_\x91\xb0\x99!\x13\xbb\xd42\x95"
    hacker_fingerprint = b"\xd0ml\xcb\xda}\xe5j\x16'\xc2\xa7\x89\x9c5\xa2\xa3\x16\xc8Q\xb3j\xd8\xed~\xd7\x84y\xbbx~\xf7"

    if cert.fingerprint(hashes.SHA256()) == solo_fingerprint:
        print("Valid SOLO firmware from SoloKeys")
    elif cert.fingerprint(hashes.SHA256()) == hacker_fingerprint:
        print("Valid HACKER firmware")
    else:
        print("Unknown fingerprint! ", cert.fingerprint(hashes.SHA256()))


@click.command()
def version():
    """Version of firmware on key."""
    try:
        major, minor, patch = solo.client.find().solo_version()
        print(f"{major}.{minor}.{patch}")
    except ApduError:
        # Older
        print("Firmware is out of date (key does not know the SOLO_VERSION command.")


@click.command()
def wink():
    """Send wink command to key (blinks LED a few times)."""
    solo.client.find().wink()


key.add_command(rng)
rng.add_command(hexbytes)
rng.add_command(raw)
key.add_command(reset)
key.add_command(version)
key.add_command(verify)
key.add_command(wink)
