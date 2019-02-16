# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
#

"""Python library for SoloKeys."""

import pathlib

__version__ = open(pathlib.Path(__file__).parent / "VERSION").read().strip()
del pathlib

from . import client
from . import dfu
from . import commands
