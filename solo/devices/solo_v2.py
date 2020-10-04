import struct

import smartcard
from fido2.client import Fido2Client
from fido2.ctap import CtapError
from fido2.ctap1 import CTAP1
from fido2.ctap2 import CTAP2
from fido2.hid import CTAPHID, CtapHidDevice
from fido2.utils import hmac_sha256

import mboot
import solo
from solo.commands import SoloBootloader
from solo.smartcard import SmartCardDevice, assert_ok

from .base import SoloClient

AID = b"\xA0\x00\x00\x08\x47\x00\x00\x00\x01"


class Client(SoloClient):
    def __init__(
        self,
    ):
        SoloClient.__init__(self)
        self.mboot_dev = None
        self.ccid_dev = None
        self.dev = None
        self.client = None
        self.is_bootloader = False

    def reboot(
        self,
    ):
        """ option to reboot after programming """
        if self.is_booted():
            self.exchange(SoloBootloader.CommandBoot)
        elif self.mboot_dev is not None:
            try:
                self.mboot_dev.reset(timeout=2000, reopen=True)
            except mboot.McuBootConnectionError:
                pass

    def is_booted(
        self,
    ):
        """ Is the application running? """
        return self.dev is not None or self.ccid_dev is not None

    def exchange(self, cmd, payload=b""):
        if self.dev is not None:
            # Using HID interface
            self.send_data_hid(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")
            return self.send_data_hid(cmd, payload)
        elif self.ccid_dev is not None:
            # Using CCID interface

            # Select root app
            res = self.ccid_dev.transmit_recv(0x00, 0xA4, 0x04, 0x00, AID)
            print(res)
            assert_ok(res)
            res = self.ccid_dev.transmit_recv(0x00, cmd, 0x00, 0x00, payload)
            return res
        else:
            if self.mboot_dev is not None:
                raise RuntimeError("Solo is currently in bootloader mode.")
            else:
                raise RuntimeError(
                    "Cannot connect to Solo via HID or CCID.  Is it connected?"
                )

    def enter_st_duf(
        self,
    ):
        raise RuntimeError(
            "DFU no longer needed on new device.  Just use regular bootloader."
        )

    def use_u2f(
        self,
    ):
        print("Warning, no U2F bridging is done on the new device anymore.")

    def use_hid(
        self,
    ):
        pass

    def find_device(self, dev=None, solo_serial=None):
        if dev is None:
            # First check HID interface
            devices = list(CtapHidDevice.list_devices())
            devices = [
                d
                for d in devices
                if d.descriptor["vendor_id"] == 0x1209
                and d.descriptor["product_id"] == 0xBEEE
            ]
            if solo_serial is not None:
                devices = [
                    d for d in devices if d.descriptor["serial_number"] == solo_serial
                ]
            if len(devices) > 1:
                raise solo.exceptions.NonUniqueDeviceError
            if len(devices) > 0:
                dev = devices[0]

        if dev is not None:
            self.dev = dev

            self.ctap1 = CTAP1(dev)
            self.ctap2 = CTAP2(dev)
            try:
                self.client = Fido2Client(dev, self.origin)
            except CtapError:
                print("Not using FIDO2 interface.")
                self.client = None

            self.send_data_hid(CTAPHID.INIT, "\x11\x11\x11\x11\x11\x11\x11\x11")
            return self.dev
        else:
            # Next check CCID interface
            for sc_device in SmartCardDevice.list_devices():
                if "SoloKeys" in sc_device._name:
                    dev = sc_device
                    print("using ccid interface")
                    self.ccid_dev = dev
                    break

            if dev is None:
                # Check for bootloader mode.
                return self.find_bootloader_device()

    def find_bootloader_device(self, dev=None, solo_serial=None):
        devices = mboot.connection.usb.RawHid.enumerate(0x1209, 0xBEEE)
        # we'll take devices that haven't had their bootroms reconfigured yet too.
        devices += mboot.connection.usb.RawHid.enumerate(0x1FC9, 0x0021)
        if len(devices):
            self.mboot_dev = mboot.McuBoot(devices[0])
            self.mboot_dev.open()
            return devices[0]

        raise RuntimeError("No devices found.")

    def get_current_hid_device(
        self,
    ):
        """ Return current device class for CTAPHID interface if available. """
        if self.dev is not None:
            return self.dev
        raise RuntimeError(
            "Cannot access CTAPHID interface.  Either device is not connected, or insufficient permissions."
        )

    def get_current_fido_client(
        self,
    ):
        """ Return current fido2 client if available. """
        if self.client is not None:
            return self.client
        raise RuntimeError(
            "Cannot access FIDO device.  Either device is not connected, or insufficient permissions."
        )

    def bootloader_version(
        self,
    ):
        return [0, 0, 0, 0]

    def solo_version(
        self,
    ):
        return [0, 0, 0, 0]

    def get_rng(self, num=0):
        ret = self.send_data_hid(SoloBootloader.CommandRNG, struct.pack("B", num))
        return ret

    def enter_solo_bootloader(
        self,
    ):
        try:
            self.exchange(SoloBootloader.CommandEnterBoot)
        except smartcard.Exceptions.CardConnectionException:
            # The device rebooting will break the connection as expected.
            pass

    def enter_bootloader_or_die(self):
        self.enter_solo_bootloader()

    def is_solo_bootloader(
        self,
    ):
        """ For now, solo bootloader could be the NXP bootrom on Solo v2. """
        pass

    def program_kbd(self, cmd):
        ctap2 = CTAP2(self.get_current_hid_device())
        return ctap2.send_cbor(0x51, cmd)

    def sign_hash(self, credential_id, dgst, pin):
        ctap2 = CTAP2(self.get_current_hid_device())
        client = self.get_current_fido_client()
        if pin:
            pin_token = client.pin_protocol.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, dgst)[:16]
            return ctap2.send_cbor(
                0x50,
                {1: dgst, 2: {"id": credential_id, "type": "public-key"}, 3: pin_auth},
            )
        else:
            return ctap2.send_cbor(
                0x50, {1: dgst, 2: {"id": credential_id, "type": "public-key"}}
            )

    def program_file(self, name):
        if self.mboot_dev is None:
            raise RuntimeError(
                "Device is not in update mode. Place in update mode first!"
            )
        print("programming", name)
        if name.lower().endswith(".bin"):
            firmware_bytes = open(name, "rb").read()
            self.mboot_dev.flash_erase_region(0, len(firmware_bytes))
            self.mboot_dev.write_memory(0, firmware_bytes)
        else:
            raise RuntimeError("Unsupported file type: " + name)
