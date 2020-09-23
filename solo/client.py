# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import base64
import json
import struct
import sys
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from fido2.attestation import Attestation
from fido2.client import Fido2Client
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1
from fido2.ctap2 import CTAP2, CredentialManagement
from fido2.hid import CTAPHID, CtapHidDevice
from fido2.utils import hmac_sha256
from fido2.webauthn import PublicKeyCredentialCreationOptions
from intelhex import IntelHex

import solo.exceptions
from solo import helpers
from solo.commands import SoloBootloader, SoloExtension


def find(solo_serial=None, retries=5, raw_device=None, udp=False):

    if udp:
        solo.fido2.force_udp_backend()

    # TODO: change `p` (for programmer) throughout
    p = SoloClient()

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
                d.descriptor["vendor_id"] == 1155,
                d.descriptor["product_id"] == 41674,
                # "Solo" in d.descriptor["product_string"],
            )
        )
    ]
    return [find(raw_device=device) for device in solo_devices]


class SoloClient:
    def __init__(self):
        self.origin = "https://example.org"
        self.host = "example.org"
        self.user_id = b"they"
        self.exchange = self.exchange_hid
        self.do_reboot = True

    def use_u2f(self):
        self.exchange = self.exchange_u2f

    def use_hid(self):
        self.exchange = self.exchange_hid

    def set_reboot(self, val):
        """ option to reboot after programming """
        self.do_reboot = val

    def reboot(self):
        """ option to reboot after programming """
        try:
            self.exchange(SoloBootloader.reboot)
        except OSError:
            pass

    def find_device(self, dev=None, solo_serial=None):
        if dev is None:
            devices = list(CtapHidDevice.list_devices())
            if solo_serial is not None:
                devices = [
                    d for d in devices if d.descriptor["serial_number"] == solo_serial
                ]
            if len(devices) > 1:
                raise solo.exceptions.NonUniqueDeviceError
            if len(devices) == 0:
                raise RuntimeError("No FIDO device found")
            dev = devices[0]
        self.dev = dev

        self.ctap1 = CTAP1(dev)
        self.ctap2 = CTAP2(dev)
        try:
            self.client = Fido2Client(dev, self.origin)
        except CtapError:
            print("Not using FIDO2 interface.")
            self.client = None

        if self.exchange == self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")

        return self.dev

    @staticmethod
    def format_request(cmd, addr=0, data=b"A" * 16):
        # not sure why this is here?
        # arr = b"\x00" * 9
        addr = struct.pack("<L", addr)
        cmd = struct.pack("B", cmd)
        length = struct.pack(">H", len(data))

        return cmd + addr[:3] + SoloBootloader.TAG + length + data

    def send_only_hid(self, cmd, data):
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        self.dev._dev.InternalSend(0x80 | cmd, bytearray(data))

    def send_data_hid(self, cmd, data):
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        with helpers.Timeout(1.0) as event:
            return self.dev.call(cmd, data, event)

    def exchange_hid(self, cmd, addr=0, data=b"A" * 16):
        req = SoloClient.format_request(cmd, addr, data)

        data = self.send_data_hid(SoloBootloader.HIDCommandBoot, req)

        ret = data[0]
        if ret != CtapError.ERR.SUCCESS:
            raise CtapError(ret)

        return data[1:]

    def exchange_u2f(self, cmd, addr=0, data=b"A" * 16):
        appid = b"A" * 32
        chal = b"B" * 32

        req = SoloClient.format_request(cmd, addr, data)

        res = self.ctap1.authenticate(chal, appid, req)

        ret = res.signature[0]
        if ret != CtapError.ERR.SUCCESS:
            raise CtapError(ret)

        return res.signature[1:]

    def exchange_fido2(self, cmd, addr=0, data=b"A" * 16):
        chal = b"B" * 32

        req = SoloClient.format_request(cmd, addr, data)

        assertion = self.ctap2.get_assertion(
            self.host, chal, [{"id": req, "type": "public-key"}]
        )

        res = assertion
        ret = res.signature[0]
        if ret != CtapError.ERR.SUCCESS:
            raise RuntimeError("Device returned non-success code %02x" % (ret,))

        return res.signature[1:]

    def bootloader_version(self):
        data = self.exchange(SoloBootloader.version)
        if len(data) > 2:
            return (data[0], data[1], data[2])
        return (0, 0, data[0])

    def solo_version(self):
        try:
            return self.send_data_hid(0x61, b"")
        except CtapError:
            data = self.exchange(SoloExtension.version)
            return (data[0], data[1], data[2])

    def write_flash(self, addr, data):
        self.exchange(SoloBootloader.write, addr, data)

    def get_rng(self, num=0):
        ret = self.send_data_hid(SoloBootloader.HIDCommandRNG, struct.pack("B", num))
        return ret

    def verify_flash(self, sig):
        """
        Tells device to check signature against application.  If it passes,
        the application will boot.
        Exception raises if signature fails.
        """
        self.exchange(SoloBootloader.done, 0, sig)

    def wink(self):
        self.send_data_hid(CTAPHID.WINK, b"")

    def ping(self, data="pong"):
        return self.send_data_hid(CTAPHID.PING, data)

    def reset(self):
        self.ctap2.reset()

    def change_pin(self, old_pin, new_pin):
        self.client.pin_protocol.change_pin(old_pin, new_pin)

    def set_pin(self, new_pin):
        self.client.pin_protocol.set_pin(new_pin)

    def make_credential(self, pin=None):
        rp = {"id": self.host, "name": "example site"}
        user = {"id": self.user_id, "name": "example user"}
        challenge = b"Y2hhbGxlbmdl"
        options = PublicKeyCredentialCreationOptions(
            rp,
            user,
            challenge,
            [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}],
        )
        attest, data = self.client.make_credential(options, pin=pin)
        try:
            attest.verify(data.hash)
        except AttributeError:
            verifier = Attestation.for_type(attest.fmt)
            verifier().verify(attest.att_statement, attest.auth_data, data.hash)
        print("Register valid")
        x5c = attest.att_statement["x5c"][0]
        cert = x509.load_der_x509_certificate(x5c, default_backend())

        return cert

    def cred_mgmt(self, pin):
        token = self.client.pin_protocol.get_pin_token(pin)
        pin_protocol = 1
        return CredentialManagement(self.ctap2, pin_protocol, token)

    def enter_solo_bootloader(self):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the bootloader
        so it can be reprogrammed
        """
        if self.exchange != self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")
        self.send_data_hid(SoloBootloader.HIDCommandEnterBoot, "")

    def enter_bootloader_or_die(self):
        try:
            self.enter_solo_bootloader()
        # except OSError:
        #     pass
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                print(
                    "Could not switch into bootloader mode.  Please hold down the button for 2s while you plug token in."
                )
                sys.exit(1)
            else:
                raise (e)

    def is_solo_bootloader(self):
        try:
            self.bootloader_version()
            return True
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                pass
            else:
                raise (e)
        return False

    def enter_st_dfu(self):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the st DFU
        so it can be reprogrammed.  Warning, you could brick your device.
        """
        soloboot = self.is_solo_bootloader()

        if soloboot or self.exchange == self.exchange_u2f:
            req = SoloClient.format_request(SoloBootloader.st_dfu)
            self.send_only_hid(SoloBootloader.HIDCommandBoot, req)
        else:
            self.send_only_hid(SoloBootloader.HIDCommandEnterSTBoot, "")

    def disable_solo_bootloader(self):
        """
        Disables the Solo bootloader.  Only do this if you want to void the possibility
        of any updates.
        If you've started from a solo hacker, make you you've programmed a final/production build!
        """
        if not self.is_solo_bootloader():
            print("Device must be in bootloader mode.")
            return False

        ret = self.exchange(
            SoloBootloader.disable, 0, b"\xcd\xde\xba\xaa"
        )  # magic number
        if ret[0] != CtapError.ERR.SUCCESS:
            print("Failed to disable bootloader")
            return False
        time.sleep(0.1)
        self.exchange(SoloBootloader.reboot)
        return True

    def program_kbd(self, cmd):
        return self.ctap2.send_cbor(0x51, cmd)

    def sign_hash(self, credential_id, dgst, pin):
        if pin:
            pin_token = self.client.pin_protocol.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, dgst)[:16]
            return self.ctap2.send_cbor(
                0x50,
                {1: dgst, 2: {"id": credential_id, "type": "public-key"}, 3: pin_auth},
            )
        else:
            return self.ctap2.send_cbor(
                0x50, {1: dgst, 2: {"id": credential_id, "type": "public-key"}}
            )

    def program_file(self, name):
        def parseField(f):
            return base64.b64decode(helpers.from_websafe(f).encode())

        def isCorrectVersion(current, target):
            """current is tuple (x,y,z).  target is string '>=x.y.z'.
            Return True if current satisfies the target expression.
            """
            if "=" in target:
                target = target.split("=")
                assert target[0] in [">", "<"]
                target_num = [int(x) for x in target[1].split(".")]
                assert len(target_num) == 3
                comp = target[0] + "="
            else:
                assert target[0] in [">", "<"]
                target_num = [int(x) for x in target[1:].split(".")]
                comp = target[0]
            target_num = (
                (target_num[0] << 16) | (target_num[1] << 8) | (target_num[2] << 0)
            )
            current_num = (current[0] << 16) | (current[1] << 8) | (current[2] << 0)
            return eval(str(current_num) + comp + str(target_num))

        if name.lower().endswith(".json"):
            data = json.loads(open(name, "r").read())
            fw = parseField(data["firmware"])
            sig = None

            if "versions" in data:
                current = (0, 0, 0)
                try:
                    current = self.bootloader_version()
                except CtapError as e:
                    if e.code == CtapError.ERR.INVALID_COMMAND:
                        pass
                    else:
                        raise (e)
                for v in data["versions"]:
                    if isCorrectVersion(current, v):
                        print("using signature version", v)
                        sig = parseField(data["versions"][v]["signature"])
                        break

                if sig is None:
                    raise RuntimeError(
                        "Improperly formatted firmware file.  Could not match version."
                    )
            else:
                sig = parseField(data["signature"])

            ih = IntelHex()
            tmp = tempfile.NamedTemporaryFile(delete=False)
            tmp.write(fw)
            tmp.seek(0)
            tmp.close()
            ih.fromfile(tmp.name, format="hex")
        else:
            if not name.lower().endswith(".hex"):
                print('Warning, assuming "%s" is an Intel Hex file.' % name)
            sig = None
            ih = IntelHex()
            ih.fromfile(name, format="hex")

        if self.exchange == self.exchange_hid:
            chunk = 2048
        else:
            chunk = 240

        seg = ih.segments()[0]
        size = seg[1] - seg[0]
        total = 0
        t1 = time.time() * 1000
        print("erasing firmware...")
        for i in range(seg[0], seg[1], chunk):
            s = i
            e = min(i + chunk, seg[1])
            data = ih.tobinarray(start=i, size=e - s)
            self.write_flash(i, data)
            total += chunk
            progress = total / float(size) * 100
            sys.stdout.write("updating firmware %.2f%%...\r" % progress)
        sys.stdout.write("updated firmware 100%             \r\n")
        t2 = time.time() * 1000
        print("time: %.2f s" % ((t2 - t1) / 1000.0))

        if sig is None:
            sig = b"A" * 64

        if self.do_reboot:
            self.verify_flash(sig)

        return sig
