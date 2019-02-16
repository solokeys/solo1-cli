import sys

import click

import solo


@click.group()
def solo_cli():
    pass


@click.command()
def version():
    print(solo.__version__)


@click.group()
def device():
    pass


@click.group()
def rng():
    pass


@click.command()
@click.option("--count", default=8, help="How many bytes to generate (defaults to 8)")
def bytes(count):
    if not 0 <= count <= 255:
        print(f"Number of bytes must be between 0 and 255, you passed {count}")
        sys.exit(1)

    p = solo.client.find()
    r = p.get_rng(count)
    print(r.hex())


@click.command()
def entropy():
    p = solo.client.find()
    while True:
        r = p.get_rng(255)
        sys.stdout.buffer.write(r)


@click.command()
def wink():
    solo.client.find().wink()


@click.command()
def version():
    solo.client.find().solo_version()


solo_cli.add_command(version)
solo_cli.add_command(device)
device.add_command(rng)
rng.add_command(bytes)
rng.add_command(entropy)
device.add_command(wink)
device.add_command(version)
