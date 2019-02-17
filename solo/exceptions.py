class NonUniqueDeviceError(Exception):
    """When specifying a potentially destructive command...

    we check that either there is exactly one applicable device,
    or demand passing the serial number (same for ST DFU bootloader
    and Solo bootloader+firmware.
    """

    pass
