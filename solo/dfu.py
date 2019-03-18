# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import struct
import time

import usb.core
import usb.util
import usb._objfinalizer

from solo.commands import DFU, STM32L4
import solo.exceptions


def find(dfu_serial=None, attempts=8, raw_device=None, altsetting=1):
    """dfu_serial is the ST bootloader serial number.

    It is not directly the ST chip identifier, but related via
    https://github.com/libopencm3/libopencm3/blob/master/lib/stm32/desig.c#L68
    """
    for i in range(attempts):
        dfu = DFUDevice()
        try:
            dfu.find(ser=dfu_serial, dev=raw_device, altsetting=altsetting)
            return dfu
        except RuntimeError:
            time.sleep(0.25)

    # return None
    raise Exception("no DFU found")


def find_all():
    st_dfus = usb.core.find(idVendor=0x0483, idProduct=0xDF11, find_all=True)
    return [find(raw_device=st_dfu) for st_dfu in st_dfus]


def hot_patch_windows_libusb():
    # hot patch for windows libusb backend
    olddel = usb._objfinalizer._AutoFinalizedObjectBase.__del__

    def newdel(self):
        try:
            olddel(self)
        except OSError:
            pass

    usb._objfinalizer._AutoFinalizedObjectBase.__del__ = newdel


class DFUDevice:
    def __init__(self,):
        pass

    @staticmethod
    def addr2list(a):
        return [a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]

    @staticmethod
    def addr2block(addr, size):
        addr -= 0x08000000
        addr //= size
        addr += 2
        return addr

    @staticmethod
    def block2addr(addr, size):
        addr -= 2
        addr *= size
        addr += 0x08000000
        return addr

    def find(self, altsetting=0, ser=None, dev=None):

        if dev is not None:
            self.dev = dev
        else:
            if ser:
                devs = usb.core.find(idVendor=0x0483, idProduct=0xDF11, find_all=True)
                eligible = [
                    d for d in devs if ser == usb.util.get_string(d, d.iSerialNumber)
                ]
                if len(eligible) > 1:
                    raise solo.exceptions.NonUniqueDeviceError
                if len(eligible) == 0:
                    raise RuntimeError("No ST DFU devices found.")

                self.dev = eligible[0]
                print("connecting to ", ser)
            else:
                eligible = list(
                    usb.core.find(idVendor=0x0483, idProduct=0xDF11, find_all=True)
                )
                if len(eligible) > 1:
                    raise solo.exceptions.NonUniqueDeviceError
                if len(eligible) == 0:
                    raise RuntimeError("No ST DFU devices found.")
                self.dev = eligible[0]

        if self.dev is None:
            raise RuntimeError("No ST DFU devices found.")
        self.dev.set_configuration()

        for cfg in self.dev:
            for intf in cfg:
                if intf.bAlternateSetting == altsetting:
                    intf.set_altsetting()
                    self.intf = intf
                    self.intNum = intf.bInterfaceNumber
                    return self.dev

        raise RuntimeError("No ST DFU alternate-%d found." % altsetting)

    # Main memory == 0
    # option bytes == 1
    def set_alt(self, alt):
        for cfg in self.dev:
            for intf in cfg:
                # print(intf, intf.bAlternateSetting)
                if intf.bAlternateSetting == alt:
                    intf.set_altsetting()
                    self.intf = intf
                    self.intNum = intf.bInterfaceNumber
                    # return self.dev

    def init(self,):
        if self.state() == DFU.state.ERROR:
            self.clear_status()

    def close(self,):
        pass

    def get_status(self,):
        # bmReqType, bmReq, wValue, wIndex, data/size
        s = self.dev.ctrl_transfer(
            DFU.type.RECEIVE, DFU.bmReq.GETSTATUS, 0, self.intNum, 6
        )
        return DFU.status(s)

    def state(self,):
        return self.get_status().state

    def clear_status(self,):
        # bmReqType, bmReq, wValue, wIndex, data/size
        _ = self.dev.ctrl_transfer(
            DFU.type.SEND, DFU.bmReq.CLRSTATUS, 0, self.intNum, None
        )

    def upload(self, block, size):
        """
        address is  ((block – 2) × size) + 0x08000000
        """
        # bmReqType, bmReq, wValue, wIndex, data/size
        return self.dev.ctrl_transfer(
            DFU.type.RECEIVE, DFU.bmReq.UPLOAD, block, self.intNum, size
        )

    def set_addr(self, addr):
        # must get_status after to take effect
        return self.dnload(0x0, [0x21] + DFUDevice.addr2list(addr))

    def dnload(self, block, data):
        # bmReqType, bmReq, wValue, wIndex, data/size
        return self.dev.ctrl_transfer(
            DFU.type.SEND, DFU.bmReq.DNLOAD, block, self.intNum, data
        )

    def erase(self, a):
        d = [0x41, a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF]
        return self.dnload(0x0, d)

    def mass_erase(self):
        # self.set_addr(0x08000000)
        # self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        # assert(DFU.state.DOWNLOAD_IDLE == self.state())
        self.dnload(0x0, [0x41])
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        assert DFU.state.DOWNLOAD_IDLE == self.state()

    def write_page(self, addr, data):
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            self.clear_status()
            self.clear_status()
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            raise RuntimeError("DFU device not in correct state for writing memory.")

        addr = DFUDevice.addr2block(addr, len(data))
        # print('flashing %d bytes to block %d/%08x...' % (len(data), addr,oldaddr))

        self.dnload(addr, data)
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        assert DFU.state.DOWNLOAD_IDLE == self.state()

    def read_mem(self, addr, size):
        addr = DFUDevice.addr2block(addr, size)

        if self.state() not in (DFU.state.IDLE, DFU.state.UPLOAD_IDLE):
            self.clear_status()
            self.clear_status()
        if self.state() not in (DFU.state.IDLE, DFU.state.UPLOAD_IDLE):
            raise RuntimeError("DFU device not in correct state for reading memory.")

        return self.upload(addr, size)

    def block_on_state(self, state):
        s = self.get_status()
        while s.state == state:
            time.sleep(s.timeout / 1000.0)
            s = self.get_status()

    def read_option_bytes(self,):
        ptr = 0x1FFF7800  # option byte address for STM32l432
        self.set_addr(ptr)
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        m = self.read_mem(0, 16)
        return m

    def write_option_bytes(self, m):
        self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        try:
            m = self.write_page(0, m)
            self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        except OSError:
            print("Warning: OSError with write_page")

    def prepare_options_bytes_detach(self,):

        # Necessary to prevent future errors...
        m = self.read_mem(0, 16)
        self.write_option_bytes(m)
        #

        m = self.read_option_bytes()
        op = struct.unpack("<L", m[:4])[0]
        oldop = op
        op |= STM32L4.options.nBOOT0
        op &= ~STM32L4.options.nSWBOOT0

        if oldop != op:
            print("Rewriting option bytes...")
            m = struct.pack("<L", op) + m[4:]
            self.write_option_bytes(m)

    def detach(self,):
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            self.clear_status()
            self.clear_status()
        if self.state() not in (DFU.state.IDLE, DFU.state.DOWNLOAD_IDLE):
            raise RuntimeError("DFU device not in correct state for detaching.")
        # self.set_addr(0x08000000)
        # self.block_on_state(DFU.state.DOWNLOAD_BUSY)
        # assert(DFU.state.DOWNLOAD_IDLE == self.state())
        self.dnload(0x0, [])
        return self.get_status()
        # return self.dev.ctrl_transfer(DFU.type.SEND, DFU.bmReq.DETACH, 0, self.intNum, None)
