import sys

import click
from cryptography.hazmat.primitives import hashes
from fido2.ctap1 import ApduError

import solo


# https://pocoo-click.readthedocs.io/en/latest/commands/#nested-handling-and-contexts
# TODO: decide where to put the switch of the transports
__DEVICE_TRANSPORT = None


@click.group()
@click.option("--transport", default="hid")
# @click.pass_context
# def device(ctx, transport):
def device(transport):
    """Interact with Solo devices, see subcommands."""
    global __DEVICE_TRANSPORT
    __DEVICE_TRANSPORT = transport
    pass


@click.group()
def rng():
    pass


@click.command()
@click.option("--count", default=8, help="How many bytes to generate (defaults to 8)")
def hexbytes(count):
    if not 0 <= count <= 255:
        print(f"Number of bytes must be between 0 and 255, you passed {count}")
        sys.exit(1)

    print(solo.client.find().get_rng(count).hex())


@click.command()
def raw():
    p = solo.client.find()
    while True:
        r = p.get_rng(255)
        sys.stdout.buffer.write(r)


@click.command()
def reset():
    if click.confirm(
        "Warning: Your credentials will be lost!!! Do you wish to continue?"
    ):
        print("Press the button to confirm -- again, your credentials will be lost!!!")
        solo.client.find().reset()
        click.echo("....aaaand they're gone")


@click.command()
def verify():
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
    try:
        major, minor, patch = solo.client.find().solo_version()
        print(f"{major}.{minor}.{patch}")
    except ApduError:
        # Older
        print("Firmware is out of date (device does not know the SOLO_VERSION command.")


@click.command()
def wink():
    solo.client.find().wink()


device.add_command(rng)
rng.add_command(hexbytes)
rng.add_command(raw)
device.add_command(reset)
device.add_command(version)
device.add_command(verify)
device.add_command(wink)
