# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import logging
import tempfile

def to_websafe(data):
    data = data.replace("+", "-")
    data = data.replace("/", "_")
    data = data.replace("=", "")
    return data


def from_websafe(data):
    data = data.replace("-", "+")
    data = data.replace("_", "/")
    return data + "=="[: (3 * len(data)) % 4]



UPGRADE_LOG_FN = tempfile.NamedTemporaryFile(prefix="nitropy.log.").name
LOG_FORMAT_STDOUT = '*** %(asctime)-15s %(levelname)6s %(name)10s %(message)s'
LOG_FORMAT = '%(relativeCreated)-8d %(levelname)6s %(name)10s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG, filename=UPGRADE_LOG_FN)
logger = logging.getLogger()

def local_print(message: str = '', exc: Exception=None, **kwargs):
    if message and message != '.':
        if exc:
            logger.exception(message, exc_info=exc)
        else:
            logger.debug('print: {}'.format(message.strip()))
    print(message, **kwargs)
