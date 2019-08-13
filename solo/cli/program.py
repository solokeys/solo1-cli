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
import usb
from fido2.ctap import CtapError

import solo
from solo.dfu import hot_patch_windows_libusb


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


    Enter dfu mode using `solo program aux enter-dfu` first.
    """

    import time

    from intelhex import IntelHex
    import usb.core

    dfu = solo.dfu.find(serial, attempts=connect_attempts)

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
                # here and below, progress would overshoot 100% otherwise
                progress = min(100, total / float(size) * 100)

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
                progress = min(100, total / float(size) * 100)
                sys.stdout.write(
                    "reading %.2f%%  %08x - %08x ...         \r"
                    % (progress, i, i + page)
                )
                if (end - start) == chunk:
                    assert data1 == data2
        print()
        print("firmware readback verified.")

    if detach:
        dfu.prepare_options_bytes_detach()
        dfu.detach()
        print("Please powercycle the device (pull out, plug in again)")

    hot_patch_windows_libusb()


program.add_command(dfu)


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.argument("firmware")  # , help="firmware (bundle) to program")
def bootloader(serial, firmware):
    """Program via Solo bootloader interface.

    \b
    FIRMWARE argument should be either a .hex or .json file.

    If the bootloader is verifying, the .json is needed containing
    a signature for the verifying key in the bootloader.

    If the bootloader is nonverifying, either .hex or .json can be used.

    DANGER: if you try to flash a firmware with signature that doesn't
    match the bootloader's verifying key, you will be stuck in bootloader
    mode until you find a signed firmware that does match.

    Enter bootloader mode using `solo program aux enter-bootloader` first.
    """

    p = solo.client.find(serial)
    try:
        p.use_hid()
        p.program_file(firmware)
    except CtapError as e:
        if e.code == CtapError.ERR.INVALID_COMMAND:
            print("Not in bootloader mode.  Attempting to switch...")
        else:
            raise e

        p.enter_bootloader_or_die()

        print("Solo rebooted.  Reconnecting...")
        time.sleep(0.5)
        p = solo.client.find(serial)
        if p is None:
            print("Cannot find Solo device.")
            sys.exit(1)
        p.use_hid()
        p.program_file(firmware)


program.add_command(bootloader)


@click.group()
def aux():
    """Auxiliary commands related to firmware/bootloader/dfu mode."""
    pass


program.add_command(aux)


def _enter_bootloader(serial):
    p = solo.client.find(serial)

    p.enter_bootloader_or_die()

    print("Solo rebooted.  Reconnecting...")
    time.sleep(0.5)
    if solo.client.find(serial) is None:
        raise RuntimeError("Failed to reconnect!")


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
def enter_bootloader(serial):
    """Switch from Solo firmware to Solo bootloader.

    Note that after powercycle, you will be in the firmware again,
    assuming it is valid.
    """

    return _enter_bootloader(serial)


aux.add_command(enter_bootloader)


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
def leave_bootloader(serial):
    """Switch from Solo bootloader to Solo firmware."""
    p = solo.client.find(serial)
    # this is a bit too low-level...
    # p.exchange(solo.commands.SoloBootloader.done, 0, b"A" * 64)
    p.reboot()


aux.add_command(leave_bootloader)


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
def enter_dfu(serial):
    """Switch from Solo bootloader to ST DFU bootloader.

    This changes the boot options of the key, which only reliably
    take effect after a powercycle.
    """

    p = solo.client.find(serial)
    p.enter_st_dfu()
    # this doesn't really work yet ;)
    # p.reboot()

    print("Please powercycle the device (pull out, plug in again)")


aux.add_command(enter_dfu)


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
def leave_dfu(serial):
    """Leave ST DFU bootloader.

    Switches to Solo bootloader or firmware, latter if firmware is valid.

    This changes the boot options of the key, which only reliably
    take effect after a powercycle.

    """

    dfu = solo.dfu.find(serial)  # select option bytes
    dfu.init()
    dfu.prepare_options_bytes_detach()
    try:
        dfu.detach()
    except usb.core.USBError:
        pass

    hot_patch_windows_libusb()
    print("Please powercycle the device (pull out, plug in again)")


aux.add_command(leave_dfu)


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
def reboot(serial):
    """Reboot.

    \b
    This should reboot from anything (firmware, bootloader, DFU).
    Separately, need to be able to set boot options.
    """

    # this implementation actually only works for bootloader
    # firmware doesn't have a reboot command
    solo.client.find(serial).reboot()


aux.add_command(reboot)


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
def bootloader_version(serial):
    """Version of bootloader."""
    p = solo.client.find(serial)
    print(".".join(map(str, p.bootloader_version())))


aux.add_command(bootloader_version)
