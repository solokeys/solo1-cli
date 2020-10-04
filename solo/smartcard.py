# With help from:
# https://github.com/Yubico/python-fido2/blob/master/fido2/pcsc.py

# Copyright (c) 2019 Yubico AB
# Copyright (c) 2019 Oleg Moiseenko
# Copyright (c) 2020 Conor Patrick
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import, unicode_literals

import logging
import struct
from binascii import b2a_hex, hexlify

import six
from smartcard import System
from smartcard.CardConnection import CardConnection
from smartcard.pcsc.PCSCContext import PCSCContext
from smartcard.pcsc.PCSCExceptions import ListReadersException

SW_SUCCESS = (0x90, 0x00)
SW_UPDATE = (0x91, 0x00)
SW1_MORE_DATA = 0x61

logger = logging.getLogger(__name__)


def _list_readers():
    try:
        return System.readers()
    except ListReadersException:
        # If the PCSC system has restarted the context might be stale, try
        # forcing a new context (This happens on Windows if the last reader is
        # removed):
        PCSCContext.instance = None
        return System.readers()


def assert_ok(response_apdu):
    code = response_apdu[-1] | (response_apdu[-2] << 8)
    assert code == 0x9000


class SmartCardDevice:
    def __init__(self, connection, name):
        self._capabilities = 0
        self.use_ext_apdu = True
        self._conn = connection
        self._conn.connect(CardConnection.T1_protocol)
        self._name = name

    def __repr__(self):
        return "SmartCardDevice(%s)" % self._name

    def _apdu_exchange(self, apdu, protocol):
        """Exchange data with smart card.
        :param apdu: byte string. data to exchange with card
        :return: byte string. response from card
        """

        logger.debug("apdu %s", b2a_hex(apdu))
        print("sending", len(list(six.iterbytes(apdu))))
        resp, sw1, sw2 = self._conn.transmit(list(six.iterbytes(apdu)), protocol)
        response = bytes(bytearray(resp))
        logger.debug("response [0x%04X] %s", sw1 << 8 + sw2, b2a_hex(response))

        return response, sw1, sw2

    def _chain_apdus(self, cla, ins, p1, p2, data=b""):
        if self.use_ext_apdu:
            print("using T1")
            header = struct.pack("!BBBBBH", cla, ins, p1, p2, 0x00, len(data))
            resp, sw1, sw2 = self._apdu_exchange(
                header + data, CardConnection.T1_protocol
            )
            return resp, sw1, sw2
        else:
            while len(data) > 250:
                to_send, data = data[:250], data[250:]
                header = struct.pack("!BBBBB", 0x10 | cla, ins, p1, p2, len(to_send))
                resp, sw1, sw2 = self._apdu_exchange(
                    header + to_send, CardConnection.T0_protocol
                )
                if (sw1, sw2) != SW_SUCCESS:
                    return resp, sw1, sw2
            apdu = struct.pack("!BBBB", cla, ins, p1, p2)
            if data:
                apdu += struct.pack("!B", len(data)) + data
            resp, sw1, sw2 = self._apdu_exchange(
                apdu + b"\x00", CardConnection.T0_protocol
            )
            while sw1 == SW1_MORE_DATA:
                apdu = b"\x00\xc0\x00\x00" + struct.pack("!B", sw2)  # sw2 == le
                lres, sw1, sw2 = self._apdu_exchange(apdu, CardConnection.T0_protocol)
                resp += lres
            return resp, sw1, sw2

    def _call_apdu(self, apdu):
        if len(apdu) >= 7 and six.indexbytes(apdu, 4) == 0:
            # Extended APDU
            data_len = struct.unpack("!H", apdu[5:7])[0]
            data = apdu[7 : 7 + data_len]
        else:
            # Short APDU
            data_len = six.indexbytes(apdu, 4)
            data = apdu[5 : 5 + data_len]
        (cla, ins, p1, p2) = six.iterbytes(apdu[:4])
        print("send %d bytes" % len(data))
        resp, sw1, sw2 = self._chain_apdus(cla, ins, p1, p2, data)
        return resp + struct.pack("!BB", sw1, sw2)

    def transmit_recv(self, cla, ins, p1, p2, data=b"", le=None):

        apdu = struct.pack("!BBBB", cla, ins, p1, p2)
        # if len(data) > 255:
        apdu += b"\x00" + struct.pack(">H", len(data))
        # else:
        # apdu += struct.pack("!B", len(data))
        apdu += data
        print("<<", hexlify(apdu).decode())
        res = self._call_apdu(apdu)
        print(">>", hexlify(res).decode())
        return res

    @classmethod
    def list_devices(cls, name=""):
        for reader in _list_readers():
            if name in reader.name:
                try:
                    yield cls(reader.createConnection(), reader.name)
                except Exception as e:
                    logger.debug("Error %r", e)


class Constants:
    class Ins:
        # Standard
        Select = 0xA4
        WriteBinary = 0xD0

        # Solo specific
        Test = 0xBE
        WriteFile = 0xBF
