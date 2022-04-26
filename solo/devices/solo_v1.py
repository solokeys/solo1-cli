import base64
import json
import struct
import sys
import tempfile
import time
from threading import Event

from fido2.client import Fido2Client
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1
from fido2.ctap2 import CTAP2
from fido2.hid import CTAPHID, CtapHidDevice
from intelhex import IntelHex

from .. import exceptions, helpers
from ..commands import SoloBootloader, SoloExtension
from .base import SoloClient


class Client(SoloClient):
    def __init__(
        self,
    ):
        SoloClient.__init__(self)
        self.exchange = self.exchange_hid

    @staticmethod
    def format_request(cmd, addr=0, data=b"A" * 16):
        # not sure why this is here?
        # arr = b"\x00" * 9
        addr = struct.pack("<L", addr)
        cmd = struct.pack("B", cmd)
        length = struct.pack(">H", len(data))

        return cmd + addr[:3] + SoloBootloader.TAG + length + data

    def reboot(
        self,
    ):
        """option to reboot after programming"""
        try:
            self.exchange(SoloBootloader.reboot)
        except OSError:
            pass

    def find_device(self, dev=None, solo_serial=None):
        if dev is None:
            devices = list(CtapHidDevice.list_devices())
            if solo_serial is not None:
                for d in devices:
                    if not hasattr(d, "serial_number"):
                        print(
                            "Currently serial numbers are not supported with current fido2 library.  Please upgrade: pip3 install fido2 --upgrade"
                        )
                        sys.exit(1)
                devices = [
                    d for d in devices if d.descriptor.serial_number == solo_serial
                ]
            if len(devices) > 1:
                raise exceptions.NonUniqueDeviceError
            if len(devices) == 0:
                raise RuntimeError("No FIDO device found")
            dev = devices[0]
        self.dev = dev

        self.ctap1 = CTAP1(dev)
        try:
            self.ctap2 = CTAP2(dev)
        except CtapError:
            self.ctap2 = None

        try:
            # Accept any RP ID, including e.g. 'solo-sign-hash:...'
            self.client = Fido2Client(dev, self.origin, verify=lambda _rp_id, _origin: True)
        except CtapError:
            print("Not using FIDO2 interface.")
            self.client = None

        if self.exchange == self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")

        return self.dev

    def get_current_hid_device(
        self,
    ):
        return self.dev

    def get_current_fido_client(
        self,
    ):
        return self.client

    def use_u2f(
        self,
    ):
        self.exchange = self.exchange_u2f

    def use_hid(
        self,
    ):
        self.exchange = self.exchange_hid

    def send_only_hid(self, cmd, data):
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])

        no_reply = Event()
        no_reply.set()
        try:
            self.dev.call(0x80 | cmd, bytearray(data), no_reply)
        except IOError:
            pass

    def exchange_hid(self, cmd, addr=0, data=b"A" * 16):
        req = Client.format_request(cmd, addr, data)

        data = self.send_data_hid(SoloBootloader.CommandBoot, req)

        ret = data[0]
        if ret != CtapError.ERR.SUCCESS:
            raise CtapError(ret)

        return data[1:]

    def exchange_u2f(self, cmd, addr=0, data=b"A" * 16):
        appid = b"A" * 32
        chal = b"B" * 32

        req = Client.format_request(cmd, addr, data)

        res = self.ctap1.authenticate(chal, appid, req)

        ret = res.signature[0]
        if ret != CtapError.ERR.SUCCESS:
            raise CtapError(ret)

        return res.signature[1:]

    def exchange_fido2(self, cmd, addr=0, data=b"A" * 16):
        chal = b"B" * 32

        req = Client.format_request(cmd, addr, data)

        assertion = self.ctap2.get_assertion(
            self.host, chal, [{"id": req, "type": "public-key"}]
        )

        res = assertion
        ret = res.signature[0]
        if ret != CtapError.ERR.SUCCESS:
            raise RuntimeError("Device returned non-success code %02x" % (ret,))

        return res.signature[1:]

    def bootloader_version(
        self,
    ):
        data = self.exchange(SoloBootloader.version)
        if len(data) > 2:
            return (data[0], data[1], data[2])
        return (0, 0, data[0])

    def solo_version(
        self,
    ):
        try:
            return self.send_data_hid(0x61, b"")
        except CtapError:
            data = self.exchange(SoloExtension.version)
            return (data[0], data[1], data[2])

    def write_flash(self, addr, data):
        self.exchange(SoloBootloader.write, addr, data)

    def get_rng(self, num=0):
        ret = self.send_data_hid(SoloBootloader.CommandRNG, struct.pack("B", num))
        return ret

    def verify_flash(self, sig):
        """
        Tells device to check signature against application.  If it passes,
        the application will boot.
        Exception raises if signature fails.
        """
        self.exchange(SoloBootloader.done, 0, sig)

    def enter_solo_bootloader(
        self,
    ):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the bootloader
        so it can be reprogrammed
        """
        if self.exchange != self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")
        self.send_data_hid(SoloBootloader.CommandEnterBoot, "")

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

    def is_solo_bootloader(
        self,
    ):
        try:
            self.bootloader_version()
            return True
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                pass
            else:
                raise (e)
        return False

    def enter_st_dfu(
        self,
    ):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the st DFU
        so it can be reprogrammed.  Warning, you could brick your device.
        """
        soloboot = self.is_solo_bootloader()

        if soloboot or self.exchange == self.exchange_u2f:
            req = Client.format_request(SoloBootloader.st_dfu)
            self.send_only_hid(SoloBootloader.CommandBoot, req)
        else:
            self.send_only_hid(SoloBootloader.CommandEnterSTBoot, "")

    def disable_solo_bootloader(
        self,
    ):
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

        total = 0
        size = sum(seg[1] - seg[0] for seg in ih.segments())

        t1 = time.time() * 1000
        print("erasing firmware...")
        for seg in ih.segments():
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
