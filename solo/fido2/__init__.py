def force_udp_backend():
    import fido2.hid

    import solo.fido2.udp_backend as udp_backend

    fido2.hid.backend = udp_backend
    fido2.hid.list_descriptors = udp_backend.list_descriptors
    fido2.hid.get_descriptor = udp_backend.get_descriptor
    fido2.hid.open_connection = udp_backend.open_connection
