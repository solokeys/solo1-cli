# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.


import binascii
import hashlib

from fido2.extensions import HmacSecretExtension

import solo.client


def simple_secret(
    secret_input,
    credential_id=None,
    relying_party="example.org",
    user_id="they",
    serial=None,
    pin=None,
):
    user_id = user_id.encode()

    client = solo.client.find(solo_serial=serial).client
    hmac_ext = HmacSecretExtension(client.ctap2)

    if credential_id is None:
        rp = {"id": relying_party, "name": "Example RP"}
        client.rp = relying_party
        client.origin = f"https://{client.rp}"
        client.user_id = user_id
        user = {"id": user_id, "name": "A. User"}
        # challenge = "Y2hhbGxlbmdl"
        challenge = "123"

        print("Touch your authenticator to generate a credential...")
        attestation_object, client_data = client.make_credential(
            rp, user, challenge, extensions=hmac_ext.create_dict(), pin=pin
        )
        credential = attestation_object.auth_data.credential_data
        credential_id = credential.credential_id

        # Show credential_id for convenience
        print(f"credential ID (hex-encoded):")
        print(credential_id.hex())
    else:
        credential_id = binascii.a2b_hex(credential_id)

    allow_list = [{"type": "public-key", "id": credential_id}]

    # challenge = 'Q0hBTExFTkdF'  # Use a new challenge for each call.
    challenge = "abc"

    # Generate a salt for HmacSecret:

    h = hashlib.sha256()
    h.update(secret_input.encode())
    salt = h.digest()
    # print(f"salt =   {salt.hex()}")

    print("Touch your authenticator to generate the response...")
    assertions, client_data = client.get_assertion(
        relying_party,
        challenge,
        allow_list,
        extensions=hmac_ext.get_dict(salt),
        pin=pin,
    )

    assertion = assertions[0]  # Only one cred in allowList, only one response.
    secret = hmac_ext.results_for(assertion.auth_data)[0]
    print("hmac-secret (hex-encoded):")
    print(secret.hex())
