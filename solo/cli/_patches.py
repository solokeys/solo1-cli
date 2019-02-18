# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

"""Monkey patch FIDO2 backend to get serial number."""

import sys

## Windows
if sys.platform.startswith("win32"):
    import fido2._pyu2f.windows

    oldDevAttrFunc = fido2._pyu2f.windows.FillDeviceAttributes
    from ctypes import wintypes
    import ctypes

    fido2._pyu2f.windows.hid.HidD_GetSerialNumberString.restype = wintypes.BOOLEAN
    fido2._pyu2f.windows.hid.HidD_GetSerialNumberString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_ulong,
    ]

    def newDevAttrFunc(device, descriptor):
        oldDevAttrFunc(device, descriptor)
        buf_ser = ctypes.create_string_buffer(1024)
        result = fido2._pyu2f.windows.hid.HidD_GetSerialNumberString(
            device, buf_ser, 1024
        )
        if result:
            descriptor.serial_number = ctypes.wstring_at(buf_ser)

    fido2._pyu2f.windows.FillDeviceAttributes = newDevAttrFunc


## macOS
if sys.platform.startswith("darwin"):
    import fido2._pyu2f.macos
    from fido2._pyu2f import base
    from fido2._pyu2f.macos import (
        iokit,
        IO_HID_DEVICE_REF,
        GetDeviceIntProperty,
        GetDevicePath,
        GetDeviceStringProperty,
        HID_DEVICE_PROPERTY_VENDOR_ID,
        HID_DEVICE_PROPERTY_PRODUCT_ID,
        HID_DEVICE_PROPERTY_PRODUCT,
        HID_DEVICE_PROPERTY_PRIMARY_USAGE,
        HID_DEVICE_PROPERTY_PRIMARY_USAGE_PAGE,
        HID_DEVICE_PROPERTY_REPORT_ID,
        cf,
    )

    HID_DEVICE_PROPERTY_SERIAL_NUMBER = b"SerialNumber"

    def newEnumerate():
        """See base class."""
        # Init a HID manager
        hid_mgr = iokit.IOHIDManagerCreate(None, None)
        if not hid_mgr:
            raise OSError("Unable to obtain HID manager reference")
        iokit.IOHIDManagerSetDeviceMatching(hid_mgr, None)

        # Get devices from HID manager
        device_set_ref = iokit.IOHIDManagerCopyDevices(hid_mgr)
        if not device_set_ref:
            raise OSError("Failed to obtain devices from HID manager")

        num = iokit.CFSetGetCount(device_set_ref)
        devices = (IO_HID_DEVICE_REF * num)()
        iokit.CFSetGetValues(device_set_ref, devices)

        # Retrieve and build descriptor dictionaries for each device
        descriptors = []
        for dev in devices:
            d = base.DeviceDescriptor()
            d.vendor_id = GetDeviceIntProperty(dev, HID_DEVICE_PROPERTY_VENDOR_ID)
            d.product_id = GetDeviceIntProperty(dev, HID_DEVICE_PROPERTY_PRODUCT_ID)
            d.product_string = GetDeviceStringProperty(dev, HID_DEVICE_PROPERTY_PRODUCT)
            d.serial_number = GetDeviceStringProperty(
                dev, HID_DEVICE_PROPERTY_SERIAL_NUMBER
            )
            d.usage = GetDeviceIntProperty(dev, HID_DEVICE_PROPERTY_PRIMARY_USAGE)
            d.usage_page = GetDeviceIntProperty(
                dev, HID_DEVICE_PROPERTY_PRIMARY_USAGE_PAGE
            )
            d.report_id = GetDeviceIntProperty(dev, HID_DEVICE_PROPERTY_REPORT_ID)
            d.path = GetDevicePath(dev)
            descriptors.append(d.ToPublicDict())

        # Clean up CF objects
        cf.CFRelease(device_set_ref)
        cf.CFRelease(hid_mgr)

        return descriptors

    fido2._pyu2f.macos.MacOsHidDevice.Enumerate = newEnumerate


## Linux
if sys.platform.startswith("linux"):
    import fido2._pyu2f.linux

    oldnewParseUevent = fido2._pyu2f.linux.ParseUevent

    def newParseUevent(uevent, desc):
        oldnewParseUevent(uevent, desc)
        lines = uevent.split(b"\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            k, v = line.split(b"=")
            if k == b"HID_UNIQ":
                desc.serial_number = v.decode("utf8")

    fido2._pyu2f.linux.ParseUevent = newParseUevent
