# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import sys
import time

import click
from fido2.ctap import CtapError

import solo


@click.group()
def program():
    """Program a key."""
    pass


# @click.command()
# def ctap():
#     """Program via CTAP (either CTAP1 or CTAP2) (assumes Solo bootloader)."""
#     pass


# program.add_command(ctap)


@click.command()
@click.option("-s", "--serial", help="serial number of DFU to use")
@click.option(
    "-a", "--connect-attempts", default=8, help="number of times to attempt connecting"
)
# @click.option("--attach", default=False, help="Attempt switching to DFU before starting")
@click.option(
    "-d",
    "--detach",
    default=False,
    is_flag=True,
    help="Reboot after successful programming",
)
@click.option("-n", "--dry-run", is_flag=True, help="Just attach and detach")
@click.argument("firmware")  # , help="firmware (bundle) to program")
def dfu(serial, connect_attempts, detach, dry_run, firmware):
    """Program via STMicroelectronics DFU interface.


    Enter this mode using `solo program lowlevel enter-dfu` first.
    """

    import time

    from intelhex import IntelHex
    import usb.core

    dfu = solo.dfu.find(dfu_serial=serial, attempts=connect_attempts)

    if dfu is None:
        print("No STU DFU device found.")
        if serial is not None:
            print("Serial number used: ", serial)
        sys.exit(1)

    dfu.init()

    if not dry_run:
        # The actual programming
        # TODO: move to `operations.py` or elsewhere
        ih = IntelHex()
        ih.fromfile(firmware, format="hex")

        chunk = 2048
        # Why is this unused
        # seg = ih.segments()[0]
        size = sum([max(x[1] - x[0], chunk) for x in ih.segments()])
        total = 0
        t1 = time.time() * 1000

        print("erasing...")
        try:
            dfu.mass_erase()
        except usb.core.USBError:
            # garbage write, sometimes needed before mass_erase
            dfu.write_page(0x08000000 + 2048 * 10, "ZZFF" * (2048 // 4))
            dfu.mass_erase()

        page = 0
        for start, end in ih.segments():
            for i in range(start, end, chunk):
                page += 1
                data = ih.tobinarray(start=i, size=chunk)
                dfu.write_page(i, data)
                total += chunk
                progress = total / float(size) * 100

                sys.stdout.write(
                    "downloading %.2f%%  %08x - %08x ...         \r"
                    % (progress, i, i + page)
                )
                # time.sleep(0.100)

            # print('done')
            # print(dfu.read_mem(i,16))

        t2 = time.time() * 1000
        print()
        print("time: %d ms" % (t2 - t1))
        print("verifying...")
        progress = 0
        for start, end in ih.segments():
            for i in range(start, end, chunk):
                data1 = dfu.read_mem(i, 2048)
                data2 = ih.tobinarray(start=i, size=chunk)
                total += chunk
                progress = total / float(size) * 100
                sys.stdout.write(
                    "reading %.2f%%  %08x - %08x ...         \r"
                    % (progress, i, i + page)
                )
                if (end - start) == chunk:
                    assert data1 == data2
        print()
        print("firmware readback verified.")

    if detach:
        dfu.detach()


program.add_command(dfu)


@click.group()
def aux():
    pass


program.add_command(aux)


@click.command()
def enter_bootloader():
    """Attempt to switch from Solo firmware to Solo bootloader."""

    p = solo.client.find()

    try:
        p.enter_solo_bootloader()
    # except OSError:
    #     pass
    except CtapError as e:
        if e.code == CtapError.ERR.INVALID_COMMAND:
            print(
                "Solo appears to not be a solo hacker.  Try holding down the button for 2 while you plug token in."
            )
            sys.exit(1)
        else:
            raise (e)
    print("Solo rebooted.  Reconnecting...")
    time.sleep(0.5)
    if solo.client.find() is None:
        raise RuntimeError("Failed to reconnect!")


aux.add_command(enter_bootloader)


@click.command()
def leave_bootloader():
    """Attempt to switch from Solo bootloader to Solo firmware."""
    raise NotImplementedError


aux.add_command(leave_bootloader)


@click.command()
def enter_dfu():
    """Attempt to switch from Solo bootloader to ST DFU bootloader."""

    p = solo.client.find()
    p.enter_st_dfu()
    # this doesn't really work yet ;)
    p.reboot()


aux.add_command(enter_dfu)


@click.command()
def leave_dfu():
    """Attempt to switch from ST DFU bootloader to (?) Solo bootloader and/or firmware."""

    dfu = solo.dfu.find()
    dfu.init()
    dfu.detach()


aux.add_command(leave_dfu)


@click.command()
def reboot():
    """Reboot.

    \b
    This should reboot from anything (firmware, bootloader, DFU).
    Separately, need to be able to set boot options.
    """
    p = solo.client.find()
    p.reboot()


aux.add_command(reboot)
