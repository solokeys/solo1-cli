# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
#
# isort:skip_file


import binascii
import hashlib
import secrets

import fido2.cose
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialParameters, PublicKeyCredentialDescriptor,
    PublicKeyCredentialType, PublicKeyCredentialRpEntity,
)

import solo.client


def make_credential(
    host="solokeys.dev",
    user_id="they",
    serial=None,
    pin=None,
    prompt="Touch your authenticator to generate a credential...",
    output=True,
    udp=False,
    algs=None
):
    if algs is None:
        algs = [fido2.cose.EdDSA.ALGORITHM, fido2.cose.ES256.ALGORITHM]

    user_id = user_id.encode()
    client = solo.client.find(solo_serial=serial, udp=udp).get_current_fido_client()

    rp = PublicKeyCredentialRpEntity(host, "Example RP")
    client.host = host
    client.origin = f"https://{client.host}"
    client.user_id = user_id
    user = fido2.webauthn.PublicKeyCredentialUserEntity(user_id, "A. User")
    challenge = secrets.token_bytes(32)

    if prompt:
        print(prompt)

    attestation_object = client.make_credential(
        {
            "rp": rp,
            "user": user,
            "challenge": challenge,
            "pubKeyCredParams": [
                PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, alg)
                for alg in algs
            ],
            "extensions": {"hmacCreateSecret": True},
        },
        pin=pin,
    ).attestation_object

    credential = attestation_object.auth_data.credential_data
    credential_id = credential.credential_id
    if output:
        print(credential_id.hex())

    return credential_id, credential.public_key


def simple_secret(
    credential_id,
    secret_input,
    host="solokeys.dev",
    user_id="they",
    serial=None,
    pin=None,
    prompt="Touch your authenticator to generate a response...",
    output=True,
    udp=False,
):
    user_id = user_id.encode()

    client = solo.client.find(solo_serial=serial, udp=udp).get_current_fido_client()

    # rp = {"id": host, "name": "Example RP"}
    client.host = host
    client.origin = f"https://{client.host}"
    client.user_id = user_id
    # user = {"id": user_id, "name": "A. User"}
    credential_id = binascii.a2b_hex(credential_id)

    allow_list = [PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credential_id)]

    challenge = secrets.token_bytes(32)

    h = hashlib.sha256()
    h.update(secret_input.encode())
    salt = h.digest()

    if prompt:
        print(prompt)

    assertion = client.get_assertion(
        {
            "rpId": host,
            "challenge": challenge,
            "allowCredentials": allow_list,
            "extensions": {"hmacGetSecret": {"salt1": salt}},
        },
        pin=pin,
    ).get_response(0)

    output = assertion.extension_results["hmacGetSecret"]["output1"]
    if output:
        print(output.hex())

    return output
