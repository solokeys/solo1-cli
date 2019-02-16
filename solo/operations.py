# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import binascii
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


def mergehex(input_hex_files, output_hex_file, attestation_key=None):
    """Merges hex files, and patches in the attestation key.

    If no attestation key is passed, uses default Solo Hacker one.

    Note that later hex files replace data of earlier ones, if they overlap.
    """

    if attestation_key is None:
        # generic / hacker attestation key
        attestation_key = (
            "1b2626ecc8f69b0f69e34fb236d76466ba12ac16c3ab5750ba064e8b90e02448"
        )

    # TODO put definitions somewhere else
    def flash_addr(num):
        return 0x08000000 + num * 2048

    PAGES = 128
    APPLICATION_END_PAGE = PAGES - 19
    AUTH_WORD_ADDR = flash_addr(APPLICATION_END_PAGE) - 8
    ATTEST_ADDR = flash_addr(PAGES - 15)

    first = IntelHex(input_hex_files[0])
    for input_hex_file in input_hex_files[1:]:
        print(f"merging {first} with {input_hex_file}")
        first.merge(IntelHex(input_hex_file), overlap="replace")

    first[flash_addr(APPLICATION_END_PAGE - 1)] = 0x41
    first[flash_addr(APPLICATION_END_PAGE - 1) + 1] = 0x41

    first[AUTH_WORD_ADDR - 4] = 0
    first[AUTH_WORD_ADDR - 1] = 0
    first[AUTH_WORD_ADDR - 2] = 0
    first[AUTH_WORD_ADDR - 3] = 0

    first[AUTH_WORD_ADDR] = 0
    first[AUTH_WORD_ADDR + 1] = 0
    first[AUTH_WORD_ADDR + 2] = 0
    first[AUTH_WORD_ADDR + 3] = 0

    first[AUTH_WORD_ADDR + 4] = 0xFF
    first[AUTH_WORD_ADDR + 5] = 0xFF
    first[AUTH_WORD_ADDR + 6] = 0xFF
    first[AUTH_WORD_ADDR + 7] = 0xFF

    # patch in the attestation key
    key = binascii.unhexlify(attestation_key)

    for i, x in enumerate(key):
        first[ATTEST_ADDR + i] = x

    first.tofile(output_hex_file, format="hex")


def sign_firmware(sk_name, hex_file):
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
    END = (0x08000000 + ((128 - 19) * 2048)) - 8

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
