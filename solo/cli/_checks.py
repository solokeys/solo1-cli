import ctypes
import os
import platform

LINUX_ROOT_WARNING = """THIS COMMAND SHOULD NOT BE RUN AS ROOT!

Please install udev rules and run `solo` as regular user (without sudo).
For more information, see: https://docs.solokeys.io/solo/udev"""

WINDOWS_CTAP_WARNING = """Try running `solo` with administrator privileges!
FIDO CTAP access is restricted on Windows 10 version 1903 and higher."""


def windows_ctap_restriction():
    win_ver = platform.sys.getwindowsversion()
    return (
        # Windows 10 1903 and higher
        win_ver.major == 10
        and win_ver.build >= 18362
        and ctypes.windll.shell32.IsUserAnAdmin() != 1
    )


def windows_checks():
    if windows_ctap_restriction():
        print(WINDOWS_CTAP_WARNING)


def linux_checks():
    if os.environ.get("ALLOW_ROOT") is None and os.geteuid() == 0:
        print(LINUX_ROOT_WARNING)


def init_checks():
    os_family = platform.sys.platform
    if os_family.startswith("linux"):
        linux_checks()
    elif os_family.startswith("win32"):
        windows_checks()
