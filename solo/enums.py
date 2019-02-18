# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

from enum import Enum


class SoloMode(Enum):
    firmware = 1
    bootloader = 2
    dfu = 3


class SoloVariant(Enum):
    secure = 1
    hacker = 2
