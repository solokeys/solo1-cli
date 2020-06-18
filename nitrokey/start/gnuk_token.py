"""
gnuk_token.py - a library for Gnuk Token

Copyright (C) 2011, 2012, 2013, 2015, 2017, 2018
              Free Software Initiative of Japan
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
import logging
from struct import *
import binascii
import usb, time
from array import array

# Possible Gnuk Token products
USB_PRODUCT_LIST=[
    { 'vendor' : 0x234b, 'product' : 0x0000 }, # FSIJ Gnuk Token
    { 'vendor' : 0x20a0, 'product' : 0x4211 }, # Nitrokey Start
    { 'vendor' : 0x1209, 'product' : 0x2440 }, # GnuPG e.V.
]

USB_PRODUCT_LIST_TUP = [
    (0x234b, 0x0000), # FSIJ Gnuk Token
    (0x20a0, 0x4211), # Nitrokey Start
    (0x1209, 0x2440), # GnuPG e.V.
]

# USB class, subclass, protocol
CCID_CLASS = 0x0B
CCID_SUBCLASS = 0x00
CCID_PROTOCOL_0 = 0x00

HID_CLASS = 0x03
HID_SUBCLASS_NO_BOOT = 0x00
HID_PROTOCOL_0 = 0x00

def icc_compose(msg_type, data_len, slot, seq, param, data):
    return pack('<BiBBBH', msg_type, data_len, slot, seq, 0, param) + data

def iso7816_compose(ins, p1, p2, data, cls=0x00, le=None):
    data_len = len(data)
    if data_len == 0:
        if not le:
            return pack('>BBBB', cls, ins, p1, p2)
        else:
            return pack('>BBBBB', cls, ins, p1, p2, le)
    else:
        if not le:
            return pack('>BBBBB', cls, ins, p1, p2, data_len) + data
        else:
            return pack('>BBBBB', cls, ins, p1, p2, data_len) \
                + data + pack('>B', le)

# This class only supports Gnuk (for now) 
class gnuk_token(object):
    def __init__(self, device, configuration, interface):
        """
        __init__(device, configuration, interface) -> None
        Initialize the device.
        device: usb.Device object.
        configuration: configuration number.
        interface: usb.Interface object representing the interface and altenate setting.
        """
        if interface.interfaceClass != CCID_CLASS:
            raise ValueError("Wrong interface class")
        if interface.interfaceSubClass != CCID_SUBCLASS:
            raise ValueError("Wrong interface sub class")
        self.__devhandle = device.open()
        self.__devhandle.claimInterface(interface)
        self.__devhandle.setAltInterface(interface)

        self.__intf = interface.interfaceNumber
        self.__alt = interface.alternateSetting
        self.__conf = configuration

        self.__hid_intf = None
        for intf in configuration.interfaces:
            for alt in intf:
                if alt.interfaceClass == HID_CLASS and \
                        alt.interfaceSubClass == HID_SUBCLASS_NO_BOOT and \
                        alt.interfaceProtocol == HID_PROTOCOL_0:
                    self.__hid_intf = alt.interfaceNumber

        self.__bulkout = 1
        self.__bulkin  = 0x81

        self.__timeout = 10000
        self.__seq = 0
        self.logger = logging.getLogger('gnuk_token')

    def set_logger(self, logger: logging.Logger):
        self.logger = logger.getChild('gnuk_token')

    def local_print(self, message: str, verbose=False):
        self.logger.debug('print: {}'.format(message))
        if verbose:
            print(message)

    def get_string(self, num):
        return self.__devhandle.getString(num, 512)

    def increment_seq(self):
        self.__seq = (self.__seq + 1) & 0xff

    def reset_device(self):
        try:
            self.__devhandle.reset()
        except:
            pass

    def release_gnuk(self):
        self.__devhandle.releaseInterface()

    def stop_gnuk(self):
        self.__devhandle.releaseInterface()
        if self.__hid_intf:
            self.__devhandle.detachKernelDriver(self.__hid_intf)
        self.__devhandle.setConfiguration(0)
        return

    def mem_info(self):
        mem = self.__devhandle.controlMsg(requestType = 0xc0, request = 0,
                                          buffer = 8, value = 0, index = 0,
                                          timeout = 10)
        start = ((mem[3]*256 + mem[2])*256 + mem[1])*256 + mem[0]
        end = ((mem[7]*256 + mem[6])*256 + mem[5])*256 + mem[4]
        return (start, end)

    def download(self, start, data, verbose=False, progress_func=None):
        addr = start
        addr_end = (start + len(data)) & 0xffffff00
        i = int((addr - 0x20000000) / 0x100)
        j = 0
        self.local_print("start %08x" % addr, verbose)
        self.local_print("end   %08x" % addr_end)
        if progress_func:
            progress_func(0)
        while addr < addr_end:
            if progress_func:
                progress_func((addr-start)/(addr_end-start))
            self.local_print("# %08x: %d : %d" % (addr, i, 256), verbose)
            self.__devhandle.controlMsg(requestType = 0x40, request = 1,
                                        buffer = data[j*256:j*256+256],
                                        value = i, index = 0, timeout = 10)
            i = i+1
            j = j+1
            addr = addr + 256
        residue = len(data) % 256
        if residue != 0:
            self.local_print("# %08x: %d : %d" % (addr, i, residue), verbose)
            self.__devhandle.controlMsg(requestType = 0x40, request = 1,
                                        buffer = data[j*256:],
                                        value = i, index = 0, timeout = 10)

    def execute(self, last_addr):
        i = int((last_addr - 0x20000000) / 0x100)
        o = (last_addr - 0x20000000) % 0x100
        self.__devhandle.controlMsg(requestType = 0x40, request = 2,
                                    buffer = None, value = i, index = o, 
                                    timeout = 10)

    def icc_get_result(self):
        usbmsg = self.__devhandle.bulkRead(self.__bulkin, 1024, self.__timeout)
        if len(usbmsg) < 10:
            self.local_print(usbmsg, True)
            raise ValueError("icc_get_result")
        msg = array('B', usbmsg)
        msg_type = msg[0]
        data_len = msg[1] + (msg[2]<<8) + (msg[3]<<16) + (msg[4]<<24)
        slot = msg[5]
        seq = msg[6]
        status = msg[7]
        error = msg[8]
        chain = msg[9]
        data = msg[10:]
        # XXX: check msg_type, data_len, slot, seq, error
        return (status, chain, data)

    def icc_get_status(self):
        msg = icc_compose(0x65, 0, 0, self.__seq, 0, b"")
        self.__devhandle.bulkWrite(self.__bulkout, msg, self.__timeout)
        self.increment_seq()
        status, chain, data = self.icc_get_result()
        # XXX: check chain, data
        return status

    def icc_power_on(self):
        msg = icc_compose(0x62, 0, 0, self.__seq, 0, b"")
        self.__devhandle.bulkWrite(self.__bulkout, msg, self.__timeout)
        self.increment_seq()
        status, chain, data = self.icc_get_result()
        # XXX: check status, chain
        self.atr = data
        return self.atr

    def icc_power_off(self):
        msg = icc_compose(0x63, 0, 0, self.__seq, 0, b"")
        self.__devhandle.bulkWrite(self.__bulkout, msg, self.__timeout)
        self.increment_seq()
        status, chain, data = self.icc_get_result()
        # XXX: check chain, data
        return status

    def icc_send_data_block(self, data):
        msg = icc_compose(0x6f, len(data), 0, self.__seq, 0, data)
        self.__devhandle.bulkWrite(self.__bulkout, msg, self.__timeout)
        self.increment_seq()
        return self.icc_get_result()

    def icc_send_cmd(self, data):
        status, chain, data_rcv = self.icc_send_data_block(data)
        if chain == 0:
            while status == 0x80:
                status, chain, data_rcv = self.icc_get_result()
            return data_rcv
        elif chain == 1:
            d = data_rcv
            while True:
                msg = icc_compose(0x6f, 0, 0, self.__seq, 0x10, b"")
                self.__devhandle.bulkWrite(self.__bulkout, msg, self.__timeout)
                self.increment_seq()
                status, chain, data_rcv = self.icc_get_result()
                # XXX: check status
                d += data_rcv
                if chain == 2:
                    break
                elif chain == 3:
                    continue
                else:
                    raise ValueError("icc_send_cmd chain")
            return d
        else:
            raise ValueError("icc_send_cmd")

    def cmd_get_response(self, expected_len):
        result = array('B')
        while True:
            cmd_data = iso7816_compose(0xc0, 0x00, 0x00, b'') + pack('>B', expected_len)
            response = self.icc_send_cmd(cmd_data)
            result += response[:-2]
            sw = response[-2:]
            if sw[0] == 0x90 and sw[1] == 0x00:
                return result
            elif sw[0] != 0x61:
                raise ValueError("%02x%02x" % (sw[0], sw[1]))
            else:
                expected_len = sw[1]

    def cmd_verify(self, who, passwd):
        cmd_data = iso7816_compose(0x20, 0x00, 0x80+who, passwd)
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_read_binary(self, fileid):
        cmd_data = iso7816_compose(0xb0, 0x80+fileid, 0x00, b'')
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return self.cmd_get_response(sw[1])

    def cmd_write_binary(self, fileid, data, is_update):
        count = 0
        data_len = len(data)
        if is_update:  # overwrite existing file -> update
            ins = 0xd6
        else:
            ins = 0xd0  # write file, and break if exist already
        while count*256 < data_len:
            if count == 0:
                if len(data) < 128:
                    cmd_data0 = iso7816_compose(ins, 0x80+fileid, 0x00, data[:128])
                    cmd_data1 = None
                else:
                    cmd_data0 = iso7816_compose(ins, 0x80+fileid, 0x00, data[:128], 0x10)
                    cmd_data1 = iso7816_compose(ins, 0x80+fileid, 0x00, data[128:256])
            else:
                if len(data[256*count:256*count+128]) < 128:
                    cmd_data0 = iso7816_compose(ins, count, 0x00, data[256*count:256*count+128])
                    cmd_data1 = None
                else:
                    cmd_data0 = iso7816_compose(ins, count, 0x00, data[256*count:256*count+128], 0x10)
                    cmd_data1 = iso7816_compose(ins, count, 0x00, data[256*count+128:256*(count+1)])
            sw = self.icc_send_cmd(cmd_data0)
            if len(sw) != 2:
                raise ValueError("cmd_write_binary 0")
            if not (sw[0] == 0x90 and sw[1] == 0x00):
                raise ValueError("cmd_write_binary 0", "%02x%02x" % (sw[0], sw[1]))
            if cmd_data1:
                sw = self.icc_send_cmd(cmd_data1)
                if len(sw) != 2:
                    raise ValueError("cmd_write_binary 1", sw)
                if not (sw[0] == 0x90 and sw[1] == 0x00):
                    raise ValueError("cmd_write_binary 1", "%02x%02x" % (sw[0], sw[1]))
            count += 1

    def cmd_select_openpgp(self):
        cmd_data = iso7816_compose(0xa4, 0x04, 0x00, b"\xD2\x76\x00\x01\x24\x01")
        r = self.icc_send_cmd(cmd_data)
        if len(r) < 2:
            raise ValueError(r)
        sw = r[-2:]
        r = r[0:-2]
        if sw[0] == 0x61:
            self.cmd_get_response(sw[1])
            return True
        elif sw[0] == 0x90 and sw[1] == 0x00:
            return True
        else:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))

    def cmd_get_data(self, tagh, tagl):
        cmd_data = iso7816_compose(0xca, tagh, tagl, b"")
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if sw[0] == 0x90 and sw[1] == 0x00:
            return array('B')
        elif sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return self.cmd_get_response(sw[1])

    def cmd_set_identity(self, ident):
        cmd_data = iso7816_compose(0x85, 0x00, ident, b"")
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_change_reference_data(self, who, data):
        cmd_data = iso7816_compose(0x24, 0x00, 0x80+who, data)
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_put_data(self, tagh, tagl, content):
        cmd_data = iso7816_compose(0xda, tagh, tagl, content)
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_put_data_odd(self, tagh, tagl, content):
        cmd_data0 = iso7816_compose(0xdb, tagh, tagl, content[:128], 0x10)
        cmd_data1 = iso7816_compose(0xdb, tagh, tagl, content[128:])
        sw = self.icc_send_cmd(cmd_data0)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        sw = self.icc_send_cmd(cmd_data1)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_reset_retry_counter(self, how, who, data):
        cmd_data = iso7816_compose(0x2c, how, who, data)
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return True

    def cmd_pso(self, p1, p2, data):
        cmd_data = iso7816_compose(0x2a, p1, p2, data)
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if sw[0] == 0x90 and sw[1] == 0x00:
            return array('B')
        elif sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return self.cmd_get_response(sw[1])

    def cmd_pso_longdata(self, p1, p2, data):
        cmd_data0 = iso7816_compose(0x2a, p1, p2, data[:128], 0x10)
        cmd_data1 = iso7816_compose(0x2a, p1, p2, data[128:])
        sw = self.icc_send_cmd(cmd_data0)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        sw = self.icc_send_cmd(cmd_data1)
        if len(sw) != 2:
            raise ValueError(sw)
        elif sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return self.cmd_get_response(sw[1])

    def cmd_internal_authenticate(self, data):
        cmd_data = iso7816_compose(0x88, 0, 0, data)
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if sw[0] == 0x90 and sw[1] == 0x00:
            return array('B')
        elif sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return self.cmd_get_response(sw[1])

    def cmd_genkey(self, keyno):
        if keyno == 1:
            data = b'\xb6\x00'
        elif keyno == 2:
            data = b'\xb8\x00'
        else:
            data = b'\xa4\x00'
        cmd_data = iso7816_compose(0x47, 0x80, 0, data)
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if sw[0] == 0x90 and sw[1] == 0x00:
            return array('B')
        elif sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        pk = self.cmd_get_response(sw[1])
        return (pk[9:9+256], pk[9+256+2:9+256+2+3])

    def cmd_get_public_key(self, keyno):
        if keyno == 1:
            data = b'\xb6\x00'
        elif keyno == 2:
            data = b'\xb8\x00'
        else:
            data = b'\xa4\x00'
        cmd_data = iso7816_compose(0x47, 0x81, 0, data)
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        elif sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        pk = self.cmd_get_response(sw[1])
        return (pk[9:9+256], pk[9+256+2:9+256+2+3])

    def cmd_put_data_remove(self, tagh, tagl):
        cmd_data = iso7816_compose(0xda, tagh, tagl, b"")
        sw = self.icc_send_cmd(cmd_data)
        if sw[0] != 0x90 and sw[1] != 0x00:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))

    def cmd_put_data_key_import_remove(self, keyno):
        if keyno == 1:
            keyspec = b"\xb6\x00"      # SIG
        elif keyno == 2:
            keyspec = b"\xb8\x00"      # DEC
        else:
            keyspec = b"\xa4\x00"      # AUT
        cmd_data = iso7816_compose(0xdb, 0x3f, 0xff, b"\x4d\x02" +  keyspec)
        sw = self.icc_send_cmd(cmd_data)
        if sw[0] != 0x90 and sw[1] != 0x00:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))

    def cmd_get_challenge(self):
        cmd_data = iso7816_compose(0x84, 0x00, 0x00, '')
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if sw[0] != 0x61:
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        return self.cmd_get_response(sw[1])

    def cmd_external_authenticate(self, keyno, signed):
        cmd_data = iso7816_compose(0x82, 0x00, keyno, signed[0:128], cls=0x10)
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))
        cmd_data = iso7816_compose(0x82, 0x00, keyno, signed[128:])
        sw = self.icc_send_cmd(cmd_data)
        if len(sw) != 2:
            raise ValueError(sw)
        if not (sw[0] == 0x90 and sw[1] == 0x00):
            raise ValueError("%02x%02x" % (sw[0], sw[1]))


class regnual(object):
    def __init__(self, dev):
        conf = dev.configurations[0]
        intf_alt = conf.interfaces[0]
        intf = intf_alt[0]
        if intf.interfaceClass != 0xff:
            raise ValueError("Wrong interface class")
        self.__devhandle = dev.open()
        self.__devhandle.claimInterface(intf)
        self.logger = logging.getLogger('regnual')

    def set_logger(self, logger: logging.Logger):
        self.logger = logger.getChild('regnual')

    def local_print(self, message: str, verbose=False):
        self.logger.debug('print: {}'.format(message))
        if verbose:
            print(message)

    def mem_info(self):
        mem = self.__devhandle.controlMsg(requestType = 0xc0, request = 0,
                                          buffer = 8, value = 0, index = 0,
                                          timeout = 10000)
        start = ((mem[3]*256 + mem[2])*256 + mem[1])*256 + mem[0]
        end = ((mem[7]*256 + mem[6])*256 + mem[5])*256 + mem[4]
        return (start, end)

    def download(self, start, data, verbose=False, progress_func = None):
        addr = start
        addr_end = (start + len(data)) & 0xffffff00
        i = int((addr - 0x08000000) / 0x100)
        j = 0
        self.local_print("start %08x" % addr, verbose)
        self.local_print("end   %08x" % addr_end, verbose)
        if progress_func:
            progress_func(0)
        while addr < addr_end:
            if progress_func:
                progress_func((addr-start)/(addr_end-start))
            self.local_print("# %08x: %d: %d : %d" % (addr, i, j, 256), verbose)
            self.__devhandle.controlMsg(requestType = 0x40, request = 1,
                                        buffer = data[j*256:j*256+256],
                                        value = 0, index = 0, timeout = 10000)
            crc32code = crc32(data[j*256:j*256+256])
            res = self.__devhandle.controlMsg(requestType = 0xc0, request = 2,
                                              buffer = 4, value = 0, index = 0,
                                              timeout = 10000)
            r_value = ((res[3]*256 + res[2])*256 + res[1])*256 + res[0]
            if (crc32code ^ r_value) != 0xffffffff:
                self.local_print("failure")
            self.__devhandle.controlMsg(requestType = 0x40, request = 3,
                                        buffer = None,
                                        value = i, index = 0, timeout = 10000)
            time.sleep(0.010)
            res = self.__devhandle.controlMsg(requestType = 0xc0, request = 2,
                                              buffer = 4, value = 0, index = 0,
                                              timeout = 10000)
            r_value = ((res[3]*256 + res[2])*256 + res[1])*256 + res[0]
            if r_value == 0:
                self.local_print("failure")
            i = i+1
            j = j+1
            addr = addr + 256
        residue = len(data) % 256
        if residue != 0:
            self.local_print("# %08x: %d : %d" % (addr, i, residue), verbose)
            self.__devhandle.controlMsg(requestType = 0x40, request = 1,
                                        buffer = data[j*256:],
                                        value = 0, index = 0, timeout = 10000)
            crc32code = crc32(data[j*256:].ljust(256,b'\xff'))
            res = self.__devhandle.controlMsg(requestType = 0xc0, request = 2,
                                              buffer = 4, value = 0, index = 0,
                                              timeout = 10000)
            r_value = ((res[3]*256 + res[2])*256 + res[1])*256 + res[0]
            if (crc32code ^ r_value) != 0xffffffff:
                self.local_print("failure")
            self.__devhandle.controlMsg(requestType = 0x40, request = 3,
                                        buffer = None,
                                        value = i, index = 0, timeout = 10000)
            time.sleep(0.010)
            res = self.__devhandle.controlMsg(requestType = 0xc0, request = 2,
                                              buffer = 4, value = 0, index = 0, 
                                              timeout = 10000)
            r_value = ((res[3]*256 + res[2])*256 + res[1])*256 + res[0]
            if r_value == 0:
                self.local_print("failure")

    def protect(self):
        self.__devhandle.controlMsg(requestType = 0x40, request = 4,
                                    buffer = None, value = 0, index = 0, 
                                    timeout = 10000)
        time.sleep(0.100)
        res = self.__devhandle.controlMsg(requestType = 0xc0, request = 2,
                                          buffer = 4, value = 0, index = 0, 
                                          timeout = 10000)
        r_value = ((res[3]*256 + res[2])*256 + res[1])*256 + res[0]
        if r_value == 0:
            self.local_print("protection failure")

    def finish(self):
        self.__devhandle.controlMsg(requestType = 0x40, request = 5,
                                    buffer = None, value = 0, index = 0, 
                                    timeout = 10000)

    def reset_device(self):
        try:
            self.__devhandle.reset()
        except:
            pass

def compare(data_original, data_in_device):
    if data_original == data_in_device:
        return True
    raise ValueError("verify failed")

def gnuk_devices():
    busses = usb.busses()
    for bus in busses:
        devices = bus.devices
        for dev in devices:
            for config in dev.configurations:
                for intf in config.interfaces:
                    for alt in intf:
                        if alt.interfaceClass == CCID_CLASS and \
                                alt.interfaceSubClass == CCID_SUBCLASS and \
                                alt.interfaceProtocol == CCID_PROTOCOL_0 and \
                                (dev.idVendor,dev.idProduct) in USB_PRODUCT_LIST_TUP:
                            yield dev, config, alt


def gnuk_devices_by_vidpid():
    busses = usb.busses()
    for bus in busses:
        devices = bus.devices
        for dev in devices:
            for cand in USB_PRODUCT_LIST:
                if dev.idVendor != cand['vendor']:
                    continue
                if dev.idProduct != cand['product']:
                    continue
                yield dev
                break

def get_gnuk_device(verbose=True, logger: logging.Logger=None):
    icc = None
    for (dev, config, intf) in gnuk_devices():
        try:
            icc = gnuk_token(dev, config, intf)
            icc.set_logger(logger)
            if logger:
                logger.debug('{} {} {}'.format(dev.filename, config.value, intf.interfaceNumber))
            if verbose:
                print("Device: %s" % dev.filename)
                print("Configuration: %d" % config.value)
                print("Interface: %d" % intf.interfaceNumber)
            break
        except:
            pass
    if not icc:
        raise ValueError("No ICC present")
    status = icc.icc_get_status()
    if status == 0:
        pass                    # It's ON already
    elif status == 1:
        icc.icc_power_on()
    else:
        raise ValueError("Unknown ICC status", status)
    return icc

SHA256_OID_PREFIX="3031300d060960864801650304020105000420"

def UNSIGNED(n):
    return n & 0xffffffff

def crc32(bytestr):
    crc = binascii.crc32(bytestr)
    return UNSIGNED(crc)

def parse_kdf_data(kdf_data):
    if len(kdf_data) == 90:
        single_salt = True
    elif len(kdf_data) == 110:
        single_salt = False
    else:
        raise ValueError("length does not much", kdf_data)

    if kdf_data[0:2] != b'\x81\x01':
        raise ValueError("data does not much")
    algo = kdf_data[2]
    if kdf_data[3:5] != b'\x82\x01':
        raise ValueError("data does not much")
    subalgo = kdf_data[5]
    if kdf_data[6:8] != b'\x83\x04':
        raise ValueError("data does not much")
    iters = unpack(">I", kdf_data[8:12])[0]
    if kdf_data[12:14] != b'\x84\x08':
        raise ValueError("data does not much")
    salt = kdf_data[14:22]
    if single_salt:
        salt_reset = None
        salt_admin = None
        if kdf_data[22:24] != b'\x87\x20':
            raise ValueError("data does not much")
        hash_user = kdf_data[24:56]
        if kdf_data[56:58] != b'\x88\x20':
            raise ValueError("data does not much")
        hash_admin = kdf_data[58:90]
    else:
        if kdf_data[22:24] != b'\x85\x08':
            raise ValueError("data does not much")
        salt_reset = kdf_data[24:32]
        if kdf_data[32:34] != b'\x86\x08':
            raise ValueError("data does not much")
        salt_admin = kdf_data[34:42]
        if kdf_data[42:44] != b'\x87\x20':
            raise ValueError("data does not much")
        hash_user = kdf_data[44:76]
        if kdf_data[76:78] != b'\x88\x20':
            raise ValueError("data does not much")
        hash_admin = kdf_data[78:110]
    return ( algo, subalgo, iters, salt, salt_reset, salt_admin,
             hash_user, hash_admin )
