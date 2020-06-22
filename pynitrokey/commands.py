# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.


class STM32L4:
    class options:
        nBOOT0 = 1 << 27
        nSWBOOT0 = 1 << 26


class SoloExtension:
    version = 0x14
    rng = 0x15


class SoloBootloader:
    write = 0x40
    done = 0x41
    check = 0x42
    erase = 0x43
    version = 0x44
    reboot = 0x45
    st_dfu = 0x46
    disable = 0x47

    HIDCommandBoot = 0x50
    HIDCommandEnterBoot = 0x51
    HIDCommandEnterSTBoot = 0x52
    HIDCommandRNG = 0x60
    HIDCommandProbe = 0x70
    HIDCommandStatus = 0x71

    TAG = b"\x8C\x27\x90\xf6"


class DFU:
    class type:
        SEND = 0x21
        RECEIVE = 0xA1

    class bmReq:
        DETACH = 0x00
        DNLOAD = 0x01
        UPLOAD = 0x02
        GETSTATUS = 0x03
        CLRSTATUS = 0x04
        GETSTATE = 0x05
        ABORT = 0x06

    class state:
        APP_IDLE = 0x00
        APP_DETACH = 0x01
        IDLE = 0x02
        DOWNLOAD_SYNC = 0x03
        DOWNLOAD_BUSY = 0x04
        DOWNLOAD_IDLE = 0x05
        MANIFEST_SYNC = 0x06
        MANIFEST = 0x07
        MANIFEST_WAIT_RESET = 0x08
        UPLOAD_IDLE = 0x09
        ERROR = 0x0A

    class status:
        def __init__(self, s):
            self.status = s[0]
            self.timeout = s[1] + (s[2] << 8) + (s[3] << 16)
            self.state = s[4]
            self.istring = s[5]
