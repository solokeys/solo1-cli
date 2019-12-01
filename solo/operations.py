# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import binascii
import struct

from intelhex import IntelHex

from solo import helpers


def genkey(output_pem_file, input_seed_file=None):
    from ecdsa import SigningKey, NIST256p
    from ecdsa.util import randrange_from_seed__trytryagain

    if input_seed_file is not None:
        seed = input_seed_file
        print("using input seed file ", seed)
        rng = open(seed, "rb").read()
        secexp = randrange_from_seed__trytryagain(rng, NIST256p.order)
        sk = SigningKey.from_secret_exponent(secexp, curve=NIST256p)
    else:
        sk = SigningKey.generate(curve=NIST256p)

    sk_name = output_pem_file
    print(f"Signing key for signing device firmware: {sk_name}")
    with open(sk_name, "wb+") as fh:
        fh.write(sk.to_pem())

    vk = sk.get_verifying_key()

    return vk


hacker_attestation_cert = b"".join(
    [
        b"0\x82\x02\xe90\x82\x02\x8e\xa0\x03\x02\x01\x02\x02\x01\x010"
        b"\n\x06\x08*\x86H\xce=\x04\x03\x020\x81\x821\x0b0\t\x06\x03U"
        b"\x04\x06\x13\x02US1\x110\x0f\x06\x03U\x04\x08\x0c\x08Maryla"
        b"nd1\x140\x12\x06\x03U\x04\n\x0c\x0bSOLO HACKER1\x100\x0e\x06"
        b"\x03U\x04\x0b\x0c\x07Root CA1\x150\x13\x06\x03U\x04\x03\x0c"
        b"\x0csolokeys.com1!0\x1f\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16"
        b"\x12hello@solokeys.com0 \x17\r181211022012Z\x18\x0f20681128"
        b"022012Z0\x81\x941\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x110\x0f"
        b"\x06\x03U\x04\x08\x0c\x08Maryland1\x140\x12\x06\x03U\x04\n\x0c"
        b'\x0bSOLO HACKER1"0 \x06\x03U\x04\x0b\x0c\x19Authenticator Atte'
        b"station1\x150\x13\x06\x03U\x04\x03\x0c\x0csolokeys.com1!0\x1f"
        b"\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x12hello@solokeys.com0Y0"
        b"\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07"
        b"\x03B\x00\x04}x\xf6\xbe\xca@v;\xc7\\\xe3\xac\xf4'\x12\xc3\x94"
        b"\x98\x137\xa6A\x0e\x92\xf6\x9a;\x15G\x8d\xb6\xce\xd9\xd3O9\x13"
        b"\xed\x12{\x81\x14;\xe8\xf9L\x968\xfe\xe3\xd6\xcb\x1bS\x93\xa2t"
        b"\xf7\x13\x9a\x0f\x9d^\xa6\xa3\x81\xde0\x81\xdb0\x1d\x06\x03U"
        b"\x1d\x0e\x04\x16\x04\x14\x9a\xfb\xa2!\t#\xb5\xe4z*\x1dzlN\x03"
        b"\x89\x92\xa3\x0e\xc20\x81\xa1\x06\x03U\x1d#\x04\x81\x990\x81"
        b"\x96\xa1\x81\x88\xa4\x81\x850\x81\x821\x0b0\t\x06\x03U\x04\x06"
        b"\x13\x02US1\x110\x0f\x06\x03U\x04\x08\x0c\x08Maryland1\x140\x12"
        b"\x06\x03U\x04\n\x0c\x0bSOLO HACKER1\x100\x0e\x06\x03U\x04\x0b\x0c"
        b"\x07Root CA1\x150\x13\x06\x03U\x04\x03\x0c\x0csolokeys.com1!0\x1f"
        b"\x06\t*\x86H\x86\xf7\r\x01\t\x01\x16\x12hello@solokeys.com\x82\t"
        b"\x00\xeb\xd4\x84P\x14\xab\xd1W0\t\x06\x03U\x1d\x13\x04\x020\x000"
        b"\x0b\x06\x03U\x1d\x0f\x04\x04\x03\x02\x04\xf00\n\x06\x08*\x86H\xce="
        b"\x04\x03\x02\x03I\x000F\x02!\x00\xa1{*\x1dNB\xa8hmea\x1e\xf5\xfem"
        b"\xc6\x99\xae| \x83\x16\xba\xd6\xe5\x0f\xd7\r~\x05\xda\xc9\x02!\x00"
        b"\x92I\xf3\x0bW\xd1\x19r\xf2uZ\xa2\xe0\xb6\xbd\x0f\x078\xd0\xe5\xa2"
        b"O\xa0\xf3\x87a\x82\xd8\xcdH\xfcW"
    ]
)


def mergehex(
    input_hex_files,
    output_hex_file,
    attestation_key=None,
    attestation_cert=None,
    APPLICATION_END_PAGE=20,
    lock=False,
):
    """Merges hex files, and patches in the attestation key.

    If no attestation key is passed, uses default Solo Hacker one.

    Note that later hex files replace data of earlier ones, if they overlap.
    """

    if attestation_key is not None and attestation_cert is None:
        raise RuntimeError("Need to provide certificate with attestation_key")
    if attestation_key is None and attestation_cert is not None:
        raise RuntimeError("Need to provide certificate with attestation_key")

    if attestation_key is None:
        # generic / hacker attestation key
        attestation_key = (
            "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448"
        )

    if attestation_cert is None:
        attestation_cert = hacker_attestation_cert
    else:
        attestation_cert = open(attestation_cert, "rb").read()
        if len(attestation_cert) < 100:
            raise RuntimeError("Attestation certificate is invalid")

    # TODO put definitions somewhere else
    def flash_addr(num):
        return 0x08000000 + num * 2048

    PAGES = 128
    APPLICATION_END_PAGE = PAGES - APPLICATION_END_PAGE
    AUTH_WORD_ADDR = flash_addr(APPLICATION_END_PAGE) - 8
    ATTEST_ADDR = flash_addr(PAGES - 15)

    print(f"app end page: {APPLICATION_END_PAGE}")
    first = IntelHex(input_hex_files[0])
    for input_hex_file in input_hex_files[1:]:
        print(f"merging {first} with {input_hex_file}")
        first.merge(IntelHex(input_hex_file), overlap="replace")

    first[flash_addr(APPLICATION_END_PAGE - 1)] = 0x41
    first[flash_addr(APPLICATION_END_PAGE - 1) + 1] = 0x41

    # authorize boot
    first[AUTH_WORD_ADDR + 0] = 0
    first[AUTH_WORD_ADDR + 1] = 0
    first[AUTH_WORD_ADDR + 2] = 0
    first[AUTH_WORD_ADDR + 3] = 0

    # make sure bootloader is enabled
    first[AUTH_WORD_ADDR + 4] = 0xFF
    first[AUTH_WORD_ADDR + 5] = 0xFF
    first[AUTH_WORD_ADDR + 6] = 0xFF
    first[AUTH_WORD_ADDR + 7] = 0xFF

    # patch in the attestation key
    key = binascii.unhexlify(attestation_key)

    for i, x in enumerate(key):
        first[ATTEST_ADDR + i] = x

    offset = 32

    # patch in device settings / i.e. lock byte in little endian 64 int.
    lock_byte = 0x02 if lock else 0x00
    device_settings = struct.pack("<Q", 0xAA551E7900000000 | lock_byte)

    for i, x in enumerate(device_settings):
        first[offset + ATTEST_ADDR + i] = x

    offset += 8

    # patch in certificate size little endian 64 int.
    cert_size = struct.pack("<Q", len(attestation_cert))

    for i, x in enumerate(cert_size):
        first[offset + ATTEST_ADDR + i] = x

    offset += 8

    # patch in certificate.
    for i, x in enumerate(attestation_cert):
        first[offset + ATTEST_ADDR + i] = x

    first.tofile(output_hex_file, format="hex")


def sign_firmware(sk_name, hex_file):
    v1 = sign_firmware_for_version(sk_name, hex_file, 19)
    v2 = sign_firmware_for_version(sk_name, hex_file, 20)

    # use fw from v2 since it's smaller.
    fw = v2["firmware"]

    return {
        "firmware": fw,
        "signature": v2["signature"],
        # signatures to use for different versions of bootloader
        "versions": {
            "<=2.5.3": {"signature": v1["signature"]},
            ">2.5.3": {"signature": v2["signature"]},
        },
    }


def sign_firmware_for_version(sk_name, hex_file, APPLICATION_END_PAGE):
    # Maybe this is not the optimal module...

    import base64

    import binascii
    from ecdsa import SigningKey
    from hashlib import sha256
    from intelhex import IntelHex

    sk = SigningKey.from_pem(open(sk_name).read())
    fw = open(hex_file, "r").read()
    fw = base64.b64encode(fw.encode())
    fw = helpers.to_websafe(fw.decode())
    ih = IntelHex()
    ih.fromfile(hex_file, format="hex")
    # start of firmware and the size of the flash region allocated for it.
    # TODO put this somewhere else.
    START = ih.segments()[0][0]
    # keep in sync with targets/stm32l432/src/memory_layout.h
    PAGES = 128
    PAGE_SIZE = 2048
    END = (0x08000000 + ((PAGES - APPLICATION_END_PAGE) * PAGE_SIZE)) - 8

    ih = IntelHex(hex_file)
    # segs = ih.segments()
    arr = ih.tobinarray(start=START, size=END - START)

    im_size = END - START

    print("im_size: ", im_size)
    print("firmware_size: ", len(arr))

    byts = (arr).tobytes() if hasattr(arr, "tobytes") else (arr).tostring()
    h = sha256()
    h.update(byts)
    sig = binascii.unhexlify(h.hexdigest())
    print("hash", binascii.hexlify(sig))
    sig = sk.sign_digest(sig)

    print("sig", binascii.hexlify(sig))

    sig = base64.b64encode(sig)
    sig = helpers.to_websafe(sig.decode())

    # msg = {'data': read()}
    msg = {"firmware": fw, "signature": sig}
    return msg
