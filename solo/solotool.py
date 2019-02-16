# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

# Programs solo using the Solo bootloader

import sys, os, time, struct, argparse
import array, struct, socket, json, base64, binascii
import tempfile
from binascii import hexlify, unhexlify
from hashlib import sha256

import click

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from fido2.hid import CtapHidDevice, CTAPHID
from fido2.client import Fido2Client, ClientError
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1, ApduError
from fido2.ctap2 import CTAP2
from fido2.utils import Timeout
from fido2.attestation import Attestation

import usb.core
import usb._objfinalizer

from intelhex import IntelHex
import serial

import solo
from solo import helpers


def get_firmware_object(sk_name, hex_file):
    # move to helpers
    return helpers.sign_firmware(sk_name, hex_file)


def attempt_to_find_device(p):
    found = False
    for i in range(0, 5):
        try:
            p.find_device()
            found = True
            break
        except RuntimeError:
            time.sleep(0.2)
    return found


def attempt_to_boot_bootloader(p):

    try:
        p.enter_solo_bootloader()
    except OSError:
        pass
    except CtapError as e:
        if e.code == CtapError.ERR.INVALID_COMMAND:
            print(
                "Solo appears to not be a solo hacker.  Try holding down the button for 2 while you plug token in."
            )
            sys.exit(1)
        else:
            raise (e)
    print("Solo rebooted.  Reconnecting...")
    time.sleep(0.500)
    if not attempt_to_find_device(p):
        raise RuntimeError("Failed to reconnect!")


def solo_main():
    # moved to new CLI
    pass


def asked_for_help():
    for i, v in enumerate(sys.argv):
        if v == "-h" or v == "--help":
            return True
    return False


def monitor_main():
    # moved to new CLI
    pass


def genkey_main():
    # moved to new CLI
    pass


def sign_main():
    # moved to new CLI
    pass


def use_dfu(args):
    fw = args.__dict__["[firmware]"]

    for i in range(0, 8):
        dfu = DFUDevice()
        try:
            dfu.find(ser=args.dfu_serial)
        except RuntimeError:
            time.sleep(0.25)
            dfu = None

    if dfu is None:
        print("No STU DFU device found. ")
        if args.dfu_serial:
            print("Serial number used: ", args.dfu_serial)
        sys.exit(1)
    dfu.init()

    if fw:
        ih = IntelHex()
        ih.fromfile(fw, format="hex")

        chunk = 2048
        seg = ih.segments()[0]
        size = sum([max(x[1] - x[0], chunk) for x in ih.segments()])
        total = 0
        t1 = time.time() * 1000

        print("erasing...")
        try:
            dfu.mass_erase()
        except usb.core.USBError:
            dfu.write_page(0x08000000 + 2048 * 10, "ZZFF" * (2048 // 4))
            dfu.mass_erase()

        page = 0
        for start, end in ih.segments():
            for i in range(start, end, chunk):
                page += 1
                s = i
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
    if args.detach:
        dfu.detach()


def programmer_main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "[firmware]",
        nargs="?",
        default="",
        help="firmware file.  Either a JSON or hex file.  JSON file contains signature while hex does not.",
    )
    parser.add_argument(
        "--use-hid",
        action="store_true",
        help="Programs using custom HID command (default).  Quicker than using U2F authenticate which is what a browser has to use.",
    )
    parser.add_argument(
        "--use-u2f",
        action="store_true",
        help="Programs using U2F authenticate. This is what a web application will use.",
    )
    parser.add_argument(
        "--no-reset",
        action="store_true",
        help="Don't reset after writing firmware.  Stay in bootloader mode.",
    )
    parser.add_argument(
        "--reset-only",
        action="store_true",
        help="Don't write anything, try to boot without a signature.",
    )
    parser.add_argument(
        "--reboot", action="store_true", help="Tell bootloader to reboot."
    )
    parser.add_argument(
        "--enter-bootloader",
        action="store_true",
        help="Don't write anything, try to enter bootloader.  Typically only supported by Solo Hacker builds.",
    )
    parser.add_argument(
        "--st-dfu",
        action="store_true",
        help="Don't write anything, try to enter ST DFU.  Warning, you could brick your Solo if you overwrite everything.  You should reprogram the option bytes just to be safe (boot to Solo bootloader first, then run this command).",
    )
    parser.add_argument(
        "--disable",
        action="store_true",
        help="Disable the Solo bootloader.  Cannot be undone.  No future updates can be applied.",
    )
    parser.add_argument(
        "--detach",
        action="store_true",
        help="Detach from ST DFU and boot from main flash.  Must be in DFU mode.",
    )
    parser.add_argument(
        "--dfu-serial",
        default="",
        help="Specify a serial number for a specific DFU device to connect to.",
    )
    parser.add_argument(
        "--use-dfu", action="store_true", help="Boot to ST-DFU before continuing."
    )
    args = parser.parse_args()

    fw = args.__dict__["[firmware]"]

    p = solo.client.SoloClient()

    try:
        p.find_device()
        if args.use_dfu:
            print("entering dfu..")
            try:
                attempt_to_boot_bootloader(p)
                p.enter_st_dfu()
            except RuntimeError:
                # already in DFU mode?
                pass
    except RuntimeError:
        print("No Solo device detected.")
        if fw or args.detach:
            use_dfu(args)
            sys.exit(0)
        else:
            sys.exit(1)

    if args.detach:
        use_dfu(args)
        sys.exit(0)

    if args.use_u2f:
        p.use_u2f()

    if args.no_reset:
        p.set_reboot(False)

    if args.enter_bootloader:
        print("Attempting to boot into bootloader mode...")
        attempt_to_boot_bootloader(p)
        sys.exit(0)

    if args.reboot:
        p.reboot()
        sys.exit(0)

    if args.st_dfu:
        print("Sending command to boot into ST DFU...")
        p.enter_st_dfu()
        sys.exit(0)

    if args.disable:
        p.disable_solo_bootloader()
        sys.exit(0)

    if fw == "" and not args.reset_only:
        print("Need to supply firmware filename, or see help for more options.")
        parser.print_help()
        sys.exit(1)

    try:
        p.bootloader_version()
    except CtapError as e:
        if e.code == CtapError.ERR.INVALID_COMMAND:
            print("Bootloader not active.  Attempting to boot into bootloader mode...")
            attempt_to_boot_bootloader(p)
        else:
            raise (e)
    except ApduError:
        print("Bootloader not active.  Attempting to boot into bootloader mode...")
        attempt_to_boot_bootloader(p)

    if args.reset_only:
        p.exchange(SoloBootloader.done, 0, b"A" * 64)
    else:
        p.program_file(fw)


def main_mergehex():
    # moved to new CLI
    pass


def main_version():
    print(solo.__version__)


def main_main():
    if sys.version_info[0] < 3:
        print("Sorry, python3 is required.")
        sys.exit(1)

    if len(sys.argv) < 2 or (len(sys.argv) == 2 and asked_for_help()):
        print("Diverse command line tool for working with Solo")
        print("usage: solotool <command> [options] [-h]")
        print("commands: program, solo, monitor, sign, genkey, mergehex, version")
        print(
            """
Examples:
    {0} program <filename.hex|filename.json>
    {0} program <all.hex> --use-dfu
    {0} program --reboot
    {0} program --enter-bootloader
    {0} program --st-dfu
    {0} solo --wink
    {0} solo --rng
    {0} monitor <serial-port>
    {0} sign <key.pem> <firmware.hex> <output.json>
    {0} genkey <output-pem-file> [rng-seed-file]
    {0} mergehex bootloader.hex solo.hex combined.hex
    {0} version
""".format(
                "solotool"
            )
        )
        sys.exit(1)

    c = sys.argv[1]
    sys.argv = sys.argv[:1] + sys.argv[2:]
    sys.argv[0] = sys.argv[0] + " " + c

    if c == "program":
        programmer_main()
    elif c == "solo":
        solo_main()
    elif c == "monitor":
        monitor_main()
    elif c == "sign":
        sign_main()
    elif c == "genkey":
        genkey_main()
    elif c == "mergehex":
        main_mergehex()
    elif c == "version":
        main_version()
    else:
        print("invalid command: %s" % c)


if __name__ == "__main__":
    main_main()
