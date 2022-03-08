import socket
import typing

from fido2.hid.base import CtapHidConnection, HidDescriptor


class UdpCtapHidConnection(CtapHidConnection):
    """CtapHidConnection implementation which uses an UDP channel"""

    def __init__(self, descriptor: HidDescriptor):
        self.descriptor = descriptor
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.remote, self.local = (
            (addr, int(port))
            for [addr, port] in (host.split(":") for host in descriptor.path.split("<"))
        )
        self.sock.bind(self.local)
        self.sock.settimeout(5.0)

    def close(self):
        self.sock.close()

    def write_packet(self, data):
        self.sock.sendto(data, self.remote)

    def read_packet(self):
        data, host = self.sock.recvfrom(self.descriptor.report_size_out)
        return data


def open_connection(descriptor: HidDescriptor) -> UdpCtapHidConnection:
    return UdpCtapHidConnection(descriptor)


def get_descriptor(path: str) -> HidDescriptor:
    return HidDescriptor(
        path, 0x1234, 0x5678, 64, 64, "software test interface", "12345678"
    )


def list_descriptors() -> typing.Iterable[HidDescriptor]:
    return map(get_descriptor, ["localhost:8111<localhost:7112"])
