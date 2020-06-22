#! /usr/bin/env python3

"""
usb_strings.py - a tool to dump USB string

Copyright (C) 2012, 2015, 2017 Free Software Initiative of Japan
Author: NIIBE Yutaka <gniibe@fsij.org>

This file is a part of Gnuk, a GnuPG USB Token implementation.

Gnuk is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Gnuk is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from pynitrokey.start.gnuk_token import *
import usb, sys

field = ['Vendor', 'Product', 'Serial', 'Revision', 'Config', 'Sys', 'Board']


def get_dict_for_device(dev: usb.Device) -> dict:
    res = {}
    handle = dev.open()
    res['name'] = dev.filename
    for i,f in enumerate(field):
        try:
            s = handle.getString(i+1, 512)
            res[f] = s.decode('UTF-8')
        except:
            res[f] = None
    return res


def get_devices() -> list:
    res = []
    for dev in gnuk_devices_by_vidpid():
        res.append(get_dict_for_device(dev=dev))
    return res


def print_device(dev: usb.Device, n:int=8) -> None:
    print("Device: %s" % dev['name'])
    for i, f in enumerate(field):
        if i > n: break
        if not dev[f]: continue
        print("%10s: %s" % (f, dev[f]))


def main(n: int) -> None:
    for dev in get_devices():
        print_device(dev, n)
    else:
        print('No devices found')


if __name__ == '__main__':
    if len(sys.argv) > 1:
        n = int(sys.argv[1])
    else:
        n = 8                   # Gnuk has eight strings
    main(n)
