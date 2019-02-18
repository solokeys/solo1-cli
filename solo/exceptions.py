# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.


class NonUniqueDeviceError(Exception):
    """When specifying a potentially destructive command...

    we check that either there is exactly one applicable device,
    or demand passing the serial number (same for ST DFU bootloader
    and Solo bootloader+firmware.
    """

    pass


class NoSoloFoundError(Exception):
    """Can signify no Solo, or missing udev rule on Linux."""

    pass
