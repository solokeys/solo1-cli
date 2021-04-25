# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import time

from fido2.hid import CtapHidDevice

import solo.exceptions

from .devices import solo_v1


def find(solo_serial=None, retries=5, raw_device=None, udp=False):

    if udp:
        print("UDP is not supported in latest version of solo-python.")
        print("Please install version solo-python==0.0.27 and fido2==8.1 to do that.")

    # Try looking for V1 device.
    p = solo_v1.Client()

    # This... is not the right way to do it yet
    p.use_u2f()

    for i in range(retries):
        try:
            p.find_device(dev=raw_device, solo_serial=solo_serial)
            return p
        except RuntimeError:
            time.sleep(0.2)

    # return None
    raise solo.exceptions.NoSoloFoundError("no Solo found")


def find_all():
    hid_devices = list(CtapHidDevice.list_devices())
    solo_devices = [
        d
        for d in hid_devices
        if all(
            (
                d.descriptor.vid == 1155,
                d.descriptor.pid == 41674,
                # "Solo" in d.descriptor["product_string"],
            )
        )
    ]
    return [find(raw_device=device) for device in solo_devices]
