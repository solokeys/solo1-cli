import socket
import sys
import fido2._pyu2f
import fido2._pyu2f.base


def force_udp_backend():
    fido2._pyu2f.InternalPlatformSwitch = _UDP_InternalPlatformSwitch


def _UDP_InternalPlatformSwitch(funcname, *args, **kwargs):
    if funcname == "__init__":
        return HidOverUDP(*args, **kwargs)
    return getattr(HidOverUDP, funcname)(*args, **kwargs)


class HidOverUDP(fido2._pyu2f.base.HidDevice):
    @staticmethod
    def Enumerate():
        a = [
            {
                "vendor_id": 0x1234,
                "product_id": 0x5678,
                "product_string": "software test interface",
                "serial_number": "12345678",
                "usage": 0x01,
                "usage_page": 0xF1D0,
                "path": "localhost:8111",
            }
        ]
        return a

    def __init__(self, path):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 7112))
        addr, port = path.split(":")
        port = int(port)
        self.token = (addr, port)
        self.sock.settimeout(1.0)

    def GetInReportDataLength(self):
        return 64

    def GetOutReportDataLength(self):
        return 64

    def Write(self, packet):
        self.sock.sendto(bytearray(packet), self.token)

    def Read(self):
        msg = [0] * 64
        pkt, _ = self.sock.recvfrom(64)
        for i, v in enumerate(pkt):
            try:
                msg[i] = ord(v)
            except TypeError:
                msg[i] = v
        return msg


# Linux fix for serial number:
if sys.platform.startswith("linux"):
    import fido2._pyu2f.linux

    # Adjust function ParseUevent from python-fido2
    def newParseUevent(uevent, desc):
        lines = uevent.split(b"\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            k, v = line.split(b"=")
            if k == b"HID_NAME":
                desc.product_string = v.decode("utf8")
            elif k == b"HID_ID":
                _, vid, pid = v.split(b":")
                desc.vendor_id = int(vid, 16)
                desc.product_id = int(pid, 16)
            elif k == b"HID_UNIQ":
                desc.serial_number = v.decode("utf8")

    fido2._pyu2f.linux.ParseUevent = newParseUevent
