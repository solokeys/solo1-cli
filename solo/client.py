import base64
import json
import struct
import sys
import tempfile
import time

from fido2.client import Fido2Client, ClientError
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1
from fido2.ctap2 import CTAP2
from fido2.hid import CtapHidDevice, CTAPHID
from fido2.utils import Timeout
from intelhex import IntelHex

from solo.commands import SoloBootloader, SoloExtension
from solo import helpers


class SoloClient:
    def __init__(self,):
        self.origin = "https://example.org"
        self.host = "example.org"
        self.exchange = self.exchange_hid
        self.do_reboot = True

    def use_u2f(self,):
        self.exchange = self.exchange_u2f

    def use_hid(self,):
        self.exchange = self.exchange_hid

    def set_reboot(self, val):
        """ option to reboot after programming """
        self.do_reboot = val

    def reboot(self,):
        """ option to reboot after programming """
        try:
            self.exchange(SoloBootloader.reboot)
        except OSError:
            pass

    def find_device(self,):
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            raise RuntimeError("No FIDO device found")
        self.dev = dev
        self.ctap1 = CTAP1(dev)
        self.ctap2 = CTAP2(dev)
        self.client = Fido2Client(dev, self.origin)

        if self.exchange == self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")

    @staticmethod
    def format_request(cmd, addr=0, data=b"A" * 16):
        arr = b"\x00" * 9
        addr = struct.pack("<L", addr)
        cmd = struct.pack("B", cmd)
        length = struct.pack(">H", len(data))

        return cmd + addr[:3] + SoloBootloader.TAG + length + data

    def send_only_hid(self, cmd, data):
        if type(data) != type(b""):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        self.dev._dev.InternalSend(0x80 | cmd, bytearray(data))

    def send_data_hid(self, cmd, data):
        if type(data) != type(b""):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        with Timeout(1.0) as event:
            return self.dev.call(cmd, data, event)

    def exchange_hid(self, cmd, addr=0, data=b"A" * 16):
        req = SoloClient.format_request(cmd, addr, data)

        data = self.send_data_hid(SoloBootloader.HIDCommandBoot, req)

        ret = data[0]
        if ret != CtapError.ERR.SUCCESS:
            str = ""
            if ret == CtapError.ERR.NOT_ALLOWED:
                str = "Out of bounds write"
            raise RuntimeError("Device returned non-success code %02x: %s" % (ret, str))

        return data[1:]

    def exchange_u2f(self, cmd, addr=0, data=b"A" * 16):
        appid = b"A" * 32
        chal = b"B" * 32

        req = SoloClient.format_request(cmd, addr, data)

        res = self.ctap1.authenticate(chal, appid, req)

        ret = res.signature[0]
        if ret != CtapError.ERR.SUCCESS:
            str = ""
            if ret == CtapError.ERR.NOT_ALLOWED:
                str = "Out of bounds write"
            raise RuntimeError("Device returned non-success code %02x: %s" % (ret, str))

        return res.signature[1:]

    def exchange_fido2(self, cmd, addr=0, data=b"A" * 16):
        chal = "B" * 32

        req = SoloClient.format_request(cmd, addr, data)

        assertions, client_data = self.client.get_assertion(
            self.host, chal, [{"id": req, "type": "public-key"}]
        )
        if len(assertions) < 1:
            raise RuntimeError("Device didn't respond to FIDO2 extended assertion")

        res = assertions[0]
        ret = res.signature[0]
        if ret != CtapError.ERR.SUCCESS:
            raise RuntimeError("Device returned non-success code %02x" % (ret,))

        return res.signature[1:]

    def bootloader_version(self,):
        data = self.exchange(SoloBootloader.version)
        if len(data) > 2:
            return (data[0], data[1], data[2])
        return data[0]

    def solo_version(self,):
        data = self.exchange_fido2(SoloExtension.version)
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

    def wink(self,):
        self.send_data_hid(CTAPHID.WINK, b"")

    def reset(self,):
        self.ctap2.reset()

    def make_credential(self,):
        rp = {"id": self.host, "name": "example site"}
        user = {"id": b"abcdef", "name": "example user"}
        challenge = "Y2hhbGxlbmdl"
        attest, data = self.client.make_credential(rp, user, challenge, exclude_list=[])
        try:
            attest.verify(data.hash)
        except AttributeError:
            verifier = Attestation.for_type(attest.fmt)
            verifier().verify(attest.att_statement, attest.auth_data, data.hash)
        print("Register valid")
        x5c = attest.att_statement["x5c"][0]
        cert = x509.load_der_x509_certificate(x5c, default_backend())

        return cert

    def enter_solo_bootloader(self,):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the bootloader
        so it can be reprogrammed
        """
        if self.exchange != self.exchange_hid:
            self.send_data_hid(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")
        self.send_data_hid(SoloBootloader.HIDCommandEnterBoot, "")

    def is_solo_bootloader(self,):
        try:
            self.bootloader_version()
            return True
        except CtapError as e:
            if e.code == CtapError.ERR.INVALID_COMMAND:
                pass
            else:
                raise (e)
        return False

    def enter_st_dfu(self,):
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

    def disable_solo_bootloader(self,):
        """
        Disables the Solo bootloader.  Only do this if you want to void the possibility
        of any updates.
        If you've started from a solo hacker, make you you've programmed a final/production build!
        """
        ret = self.exchange(
            SoloBootloader.disable, 0, b"\xcd\xde\xba\xaa"
        )  # magic number
        if ret[0] != CtapError.ERR.SUCCESS:
            print("Failed to disable bootloader")
            return False
        time.sleep(0.1)
        self.exchange(SoloBootloader.do_reboot)
        return True

    def program_file(self, name):

        if name.lower().endswith(".json"):
            data = json.loads(open(name, "r").read())
            fw = base64.b64decode(helpers.from_websafe(data["firmware"]).encode())
            sig = base64.b64decode(helpers.from_websafe(data["signature"]).encode())
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
        print("erasing...")
        for i in range(seg[0], seg[1], chunk):
            s = i
            e = min(i + chunk, seg[1])
            data = ih.tobinarray(start=i, size=e - s)
            self.write_flash(i, data)
            total += chunk
            progress = total / float(size) * 100
            sys.stdout.write("downloading %.2f%%...\r" % progress)
        sys.stdout.write("downloaded 100%             \r\n")
        t2 = time.time() * 1000
        print("time: %.2f s" % ((t2 - t1) / 1000.0))

        print("Verifying...")
        if self.do_reboot:
            if sig is not None:
                self.verify_flash(sig)
            else:
                self.verify_flash(b"A" * 64)


def find():
    p = SoloClient()
    p.find_device()
    return p
