# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.

import base64
import getpass
import hashlib
import os
import pathlib
import sys
import time

import click
from cryptography.hazmat.primitives import hashes
from fido2.client import ClientError as Fido2ClientError
from fido2.ctap import CtapError
from fido2.ctap1 import ApduError
from fido2.ctap2 import CredentialManagement
import fido2.cose

import solo
import solo.fido2
from solo.cli.update import update


# https://pocoo-click.readthedocs.io/en/latest/commands/#nested-handling-and-contexts
@click.group()
def key():
    """Interact with Solo keys, see subcommands."""
    pass


@click.group(name="credential")
def cred():
    """Credential management, see subcommands."""
    pass


@click.group()
def rng():
    """Access TRNG on key, see subcommands."""
    pass


@click.command()
@click.option("--count", default=8, help="How many bytes to generate (defaults to 8)")
@click.option("-s", "--serial", help="Serial number of Solo to use")
def hexbytes(count, serial):
    """Output COUNT number of random bytes, hex-encoded."""
    if not 0 <= count <= 255:
        print(f"Number of bytes must be between 0 and 255, you passed {count}")
        sys.exit(1)

    print(solo.client.find(serial).get_rng(count).hex())


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
def raw(serial):
    """Output raw entropy endlessly."""
    p = solo.client.find(serial)
    while True:
        r = p.get_rng(255)
        sys.stdout.buffer.write(r)


@click.command()
@click.option("--count", default=64, help="How many bytes to generate (defaults to 8)")
@click.option("-s", "--serial", help="Serial number of Solo to use")
def feedkernel(count, serial):
    """Feed random bytes to /dev/random."""

    if os.name != "posix":
        print("This is a Linux-specific command!")
        sys.exit(1)

    if not 0 <= count <= 255:
        print(f"Number of bytes must be between 0 and 255, you passed {count}")
        sys.exit(1)

    p = solo.client.find(serial)

    import fcntl
    import struct

    RNDADDENTROPY = 0x40085203

    entropy_info_file = "/proc/sys/kernel/random/entropy_avail"
    print(f"Entropy before: 0x{open(entropy_info_file).read().strip()}")

    r = p.get_rng(count)

    # man 4 random

    # RNDADDENTROPY
    #       Add some additional entropy to the input pool, incrementing the
    #       entropy count. This differs from writing to /dev/random or
    #       /dev/urandom, which only adds some data but does not increment the
    #       entropy count. The following structure is used:

    #           struct rand_pool_info {
    #               int    entropy_count;
    #               int    buf_size;
    #               __u32  buf[0];
    #           };

    #       Here entropy_count is the value added to (or subtracted from) the
    #       entropy count, and buf is the buffer of size buf_size which gets
    #       added to the entropy pool.

    entropy_bits_per_byte = 2  # maximum 8, tend to be pessimistic
    t = struct.pack(f"ii{count}s", count * entropy_bits_per_byte, count, r)

    with open("/dev/random", mode="wb") as fh:
        fcntl.ioctl(fh, RNDADDENTROPY, t)
    print(f"Entropy after:  0x{open(entropy_info_file).read().strip()}")


@click.command()
def list_algorithms():
    """Display algorithms supported by client.

    These can be passed to `solo key make-credential`.
    """

    alg_names = (fido2.cose.CoseKey.for_alg(alg).__name__ for alg in fido2.cose.CoseKey.supported_algorithms())
    print(f"Supported algorithms: {', '.join(alg_names)}")


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo use")
@click.option(
    "--host", help="Relying party's host  [default: solokeys.dev]", default=None
)
@click.option("--default-sign-host", is_flag=True, default=False,
              help="Set host to default value for sign-file, shorthand for --host 'solo-sign-hash:'")
@click.option("--user", help="User ID", default="they", show_default=True)
@click.option("--pin", help="PIN", default=None)
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
@click.option(
    "--prompt",
    help="Prompt for user",
    default="Touch your authenticator to generate a credential...",
    show_default=True,
)
@click.option("--alg", default="EdDSA,ES256", show_default=True,
              help="Algorithm(s) for key, separated by ',', in order of preference")
@click.option("--no-pubkey", is_flag=True, default=False, help="Do not display public key")
@click.option("--minisign", is_flag=True, default=False,
              help="Display public key in Minisign-compatible format and set host to 'solo-sign-hash:' for sign-hash")
@click.option("--key-file", default=None, help="File to store public key (use with --minisign)")
@click.option("--key-id", default=None, help="Key ID to write to key file (8 bytes as HEX) (use with --key-file)"
                                             " [default: <hash of credential ID>]")
@click.option("--untrusted-comment", default=None,
              help="Untrusted comment to write to public key file (use with --key-file) [default: <key ID>]")
def make_credential(serial, host, default_sign_host, user, udp, prompt, pin,
                    alg, no_pubkey, minisign, key_file, key_id, untrusted_comment):
    """Generate a credential.

    Pass `--prompt "" --no-pubkey` to output only the `credential_id` as hex.
    """

    import solo.hmac_secret

    algs = [fido2.cose.CoseKey.for_name(a).ALGORITHM for a in alg.split(",")]
    if None in algs:
        print("Error: Unknown algorithm(s): ", [a for a, aid in zip(alg.split(","), algs) if aid is None])
        sys.exit(1)

    if default_sign_host:
        if host is not None:
            print("Error: Cannot specify both --host and --default-sign-host")
            sys.exit(2)
        host = "solo-sign-hash:"
    elif host is None:
        host = "solokeys.dev"

    # check for PIN
    if not pin:
        pin = getpass.getpass("PIN (leave empty for no PIN): ")
    if not pin:
        pin = None

    cred_id, pk = solo.hmac_secret.make_credential(
        host=host,
        user_id=user,
        serial=serial,
        output=True,
        prompt=prompt,
        udp=udp,
        pin=pin,
        algs=algs
    )

    pk_bytes = pk[-2]

    if minisign:
        if pk.ALGORITHM != fido2.cose.EdDSA.ALGORITHM:
            print(f"Error: Minisign only supports EdDSA keys but this credential was created using {type(pk).__name__}")
            sys.exit(1)

        if key_id is not None:
            key_id_hex = key_id
            key_id = int(key_id, 16).to_bytes(8, "little")
        else:
            key_id = hashlib.blake2b(cred_id).digest()[:8]
            # key_id is interpreted as little endian integer and then converted to hex (omitting leading zeros)
            key_id_hex = f"{int.from_bytes(key_id, 'little'):X}"

        minisign_pk = base64.b64encode(b"Ed" + key_id + pk_bytes)
        if not no_pubkey:
            print(f"Public key ({type(pk).__name__}) {key_id_hex} (Minisign Base64): {minisign_pk.decode()}")

    elif not no_pubkey:
        print(f"Public key ({type(pk).__name__}) (HEX): {pk_bytes.hex()}")

    if key_file is not None:
        if minisign:
            if untrusted_comment is not None:
                untrusted_comment_bytes = untrusted_comment.encode()
            else:
                untrusted_comment_bytes = b"minisign solokey public key " + key_id_hex.encode()

            with open(key_file, "wb") as f:
                f.write(b"untrusted comment: ")
                f.write(untrusted_comment_bytes)
                f.write(b"\n")
                f.write(minisign_pk)
                f.write(b"\n")

            print(f"Minisign public key written to {key_file}")

        else:
            print("Writing key file is only supported for minisign keys")


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo use")
@click.option("--host", help="Relying party's host", default="solokeys.dev")
@click.option("--user", help="User ID", default="they")
@click.option("--pin", help="PIN", default=None)
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
@click.option(
    "--prompt",
    help="Prompt for user",
    default="Touch your authenticator to generate a reponse...",
    show_default=True,
)
@click.argument("credential-id")
@click.argument("challenge")
def challenge_response(serial, host, user, prompt, credential_id, challenge, udp, pin):
    """Uses `hmac-secret` to implement a challenge-response mechanism.

    We abuse hmac-secret, which gives us `HMAC(K, hash(challenge))`, where `K`
    is a secret tied to the `credential_id`. We hash the challenge first, since
    a 32 byte value is expected (in original usage, it's a salt).

    This means that we first need to setup a credential_id; this depends on the
    specific authenticator used. To do this, use `solo key make-credential`.

    If so desired, user and relying party can be changed from the defaults.

    The prompt can be suppressed using `--prompt ""`.
    """

    import solo.hmac_secret

    # check for PIN
    if not pin:
        pin = getpass.getpass("PIN (leave empty for no PIN): ")
    if not pin:
        pin = None

    solo.hmac_secret.simple_secret(
        credential_id,
        challenge,
        host=host,
        user_id=user,
        serial=serial,
        prompt=prompt,
        output=True,
        udp=udp,
        pin=pin,
    )


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo use")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
@click.argument("hash-type")
@click.argument("filename")
def probe(serial, udp, hash_type, filename):
    """Calculate HASH."""

    # hash_type = hash_type.upper()
    assert hash_type in ("SHA256", "SHA512", "RSA2048", "Ed25519")

    data = open(filename, "rb").read()
    # < CTAPHID_BUFFER_SIZE
    # https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb-message-and-packet-structure
    # also account for padding (see data below....)
    # so 6kb is conservative
    assert len(data) <= 6 * 1024

    p = solo.client.find(serial, udp=udp)
    import fido2

    serialized_command = fido2.cbor.dumps({"subcommand": hash_type, "data": data})
    from solo.commands import SoloBootloader

    result = p.send_data_hid(SoloBootloader.HIDCommandProbe, serialized_command)
    result_hex = result.hex()
    print(result_hex)
    if hash_type == "Ed25519":
        print(f"content: {result[64:]}")
        # print(f"content from hex: {bytes.fromhex(result_hex[128:]).decode()}")
        print(f"content from hex: {bytes.fromhex(result_hex[128:])}")
        print(f"signature: {result[:128]}")
        import nacl.signing

        # verify_key = nacl.signing.VerifyKey(bytes.fromhex("c69995185efa20bf7a88139f5920335aa3d3e7f20464345a2c095c766dfa157a"))
        verify_key = nacl.signing.VerifyKey(
            bytes.fromhex(
                "c69995185efa20bf7a88139f5920335aa3d3e7f20464345a2c095c766dfa157a"
            )
        )
        try:
            verify_key.verify(result)
            verified = True
        except nacl.exceptions.BadSignatureError:
            verified = False
        print(f"verified? {verified}")
    # print(fido2.cbor.loads(result))


# @click.command()
# @click.option("-s", "--serial", help="Serial number of Solo to use")
# @click.argument("filename")
# def sha256sum(serial, filename):
#     """Calculate SHA256 hash of FILENAME."""

#     data = open(filename, 'rb').read()
#     # CTAPHID_BUFFER_SIZE
#     # https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb-message-and-packet-structure
#     assert len(data) <= 7609
#     p = solo.client.find(serial)
#     sha256sum = p.calculate_sha256(data)
#     print(sha256sum.hex().lower())

# @click.command()
# @click.option("-s", "--serial", help="Serial number of Solo to use")
# @click.argument("filename")
# def sha512sum(serial, filename):
#     """Calculate SHA512 hash of FILENAME."""

#     data = open(filename, 'rb').read()
#     # CTAPHID_BUFFER_SIZE
#     # https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb-message-and-packet-structure
#     assert len(data) <= 7609
#     p = solo.client.find(serial)
#     sha512sum = p.calculate_sha512(data)
#     print(sha512sum.hex().lower())


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
def reset(serial):
    """Reset key - wipes all credentials!!!"""
    if click.confirm(
        "Warning: Your credentials will be lost!!! Do you wish to continue?"
    ):
        print("Press the button to confirm -- again, your credentials will be lost!!!")
        solo.client.find(serial).reset()
        click.echo("....aaaand they're gone")


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
# @click.option("--new-pin", help="change current pin")
def change_pin(serial):
    """Change pin of current key"""
    old_pin = getpass.getpass("Please enter old pin: ")
    new_pin = getpass.getpass("Please enter new pin: ")
    confirm_pin = getpass.getpass("Please confirm new pin: ")
    if new_pin != confirm_pin:
        click.echo("New pin are mismatched. Please try again!")
        return
    try:
        solo.client.find(serial).change_pin(old_pin, new_pin)
        click.echo("Done. Please use new pin to verify key")
    except Exception as e:
        print(e)


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
# @click.option("--new-pin", help="change current pin")
def set_pin(serial):
    """Set pin of current key"""
    new_pin = getpass.getpass("Please enter new pin: ")
    confirm_pin = getpass.getpass("Please confirm new pin: ")
    if new_pin != confirm_pin:
        click.echo("New pin are mismatched. Please try again!")
        return
    try:
        solo.client.find(serial).set_pin(new_pin)
        click.echo("Done. Please use new pin to verify key")
    except Exception as e:
        print(e)


@click.command()
@click.option("--pin", help="PIN for to access key")
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
def verify(pin, serial, udp):
    """Verify key is valid Solo Secure or Solo Hacker."""

    key = solo.client.find(serial, udp=udp)

    if (
        key.client
        and ("clientPin" in key.client.info.options)
        and key.client.info.options["clientPin"]
        and not pin
    ):
        pin = getpass.getpass("PIN: ")

    # Any longer and this needs to go in a submodule
    print("Please press the button on your Solo key")
    try:
        cert = key.make_credential(pin=pin)
    except Fido2ClientError as e:
        cause = str(e.cause)
        if "PIN required" in cause:
            print("Your key has a PIN set but none was provided.")
            sys.exit(1)
        # error 0x31
        if "PIN_INVALID" in cause:
            print("Your key has a different PIN. Please try to remember it :)")
            sys.exit(1)
        # error 0x34 (power cycle helps)
        if "PIN_AUTH_BLOCKED" in cause:
            print(
                "Your key's PIN authentication is blocked due to too many incorrect attempts."
            )
            print("Please plug it out and in again, then again!")
            print(
                "Please be careful, after too many incorrect attempts, the key will fully block."
            )
            sys.exit(1)
        # error 0x32 (only reset helps)
        if "PIN_BLOCKED" in cause:
            print(
                "Your key's PIN is blocked. To use it again, you need to fully reset it."
            )
            print("You can do this using: `solo key reset`")
            sys.exit(1)
        # error 0x01
        if "INVALID_COMMAND" in cause:
            print("Error getting credential, is your key in bootloader mode?")
            print("Try: `solo program aux leave-bootloader`")
            sys.exit(1)
        raise

    fingerprints = [
        {
            "fingerprint": b"r\xd5\x831&\xac\xfc\xe9\xa8\xe8&`\x18\xe6AI4\xc8\xbeJ\xb8h_\x91\xb0\x99!\x13\xbb\xd42\x95",
            "msg": "Valid Solo (<=3.0.0) firmware from SoloKeys.",
        },
        {
            "fingerprint": b"\xd0ml\xcb\xda}\xe5j\x16'\xc2\xa7\x89\x9c5\xa2\xa3\x16\xc8Q\xb3j\xd8\xed~\xd7\x84y\xbbx~\xf7",
            "msg": "Solo Hacker firmware.",
        },
        {
            "fingerprint": b"\x05\x92\xe1\xb2\xba\x8ea\rb\x9a\x9b\xc0\x15\x19~J\xda\xdc16\xe0\xa0\xa1v\xd9\xb5}\x17\xa6\xb8\x0b8",
            "msg": "Local software emulation.",
        },
        {
            "fingerprint": b"\xb3k\x03!\x11d\xdb\x1d`A>\xc0\xf8\xd8'\xe0\xee\xc2\x04\xbe)\x06S\x00\x94\x0e\xd9\xc5\x9b\x90S?",
            "msg": "Valid Solo Tap with firmware from SoloKeys.",
        },
        {
            "fingerprint": b"\x8d\xde\x12\xdb\x98\xe8|\x90\xc9\xd6#\x1a\x9c\xd8\xfe?T\xdf\x82\xb7=s.\x8er\xec\x9f\x98\xf8\xb5\xc6\xc1",
            "msg": "Valid Somu with firmware from SoloKeys.",
        },
        {
            "fingerprint": b"2u\x85\xe4\x9eIl\xff\xde\xbcK(\x06\x08\x1814\xe7\xcb\xf4\xc0\x16pg\x94v)\x1c\xd9\xb9\x81\x04",
            "msg": "Valid Solo with firmware from SoloKeys.",
        },
    ]

    known = False
    for f in fingerprints:
        if cert.fingerprint(hashes.SHA256()) == f["fingerprint"]:
            print(f["msg"])
            known = True
            break

    if not known:
        print("Unknown fingerprint! ", cert.fingerprint(hashes.SHA256()))


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
def version(serial, udp):
    """Version of firmware on key."""

    try:
        res = solo.client.find(serial, udp=udp).solo_version()
        major, minor, patch = res[:3]
        locked = ""
        if len(res) > 3:
            if res[3]:
                locked = "locked"
            else:
                locked = "unlocked"
        print(f"{major}.{minor}.{patch} {locked}")

    except solo.exceptions.NoSoloFoundError:
        print("No Solo found.")
        print("If you are on Linux, are your udev rules up to date?")
    except (solo.exceptions.NoSoloFoundError, ApduError):
        # Older
        print("Firmware is out of date (key does not know the SOLO_VERSION command).")


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
def wink(serial, udp):
    """Send wink command to key (blinks LED a few times)."""

    solo.client.find(serial, udp=udp).wink()


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
@click.option("--ping-data", default="pong", help="Data to send (default: pong)")
def ping(serial, udp, ping_data):
    """Send ping command to key"""

    client = solo.client.find(serial, udp=udp)
    start = time.time()
    res = client.ping(ping_data)
    end = time.time()
    duration = int((end - start) * 1000)
    print(f"ping returned: {res}")
    print(f"took {duration} ms")


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.argument("sequence")
def keyboard(serial, sequence):
    """Program the specified key sequence to Solo"""

    dev = solo.client.find(serial)
    buf = sequence.encode("ascii")
    if len(buf) > 64:
        print("Keyboard sequence cannot exceed 64 bytes")
    else:
        dev.program_kbd(buf)


@click.command()
@click.option("-s", "--serial", help="Serial number of Solo to use")
def disable_updates(serial):
    """Permanently disable firmware updates on Solo.  Cannot be undone.  Solo must be in bootloader mode."""

    dev = solo.client.find(serial)
    dev.use_hid()
    if dev.disable_solo_bootloader():
        print(
            "Success, firmware updates have been permanently disabled on this device."
        )
        print("You will not be able to access bootloader mode again.")
    else:
        print("Failed to disable the firmware update.")


@click.command(name="info")
@click.option("--pin", help="PIN for to access key")
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
def cred_info(pin, serial, udp):
    """Get credentials metadata"""
    if not pin:
        pin = getpass.getpass("PIN: ")

    client = solo.client.find(serial, udp=udp)
    cm = client.cred_mgmt(pin)
    meta = cm.get_metadata()
    existing = meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
    remaining = meta[CredentialManagement.RESULT.MAX_REMAINING_COUNT]
    print("Existing resident keys: {}".format(existing))
    print("Remaining resident keys: {}".format(remaining))


@click.command(name="ls")
@click.option("--pin", help="PIN for to access key")
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
def cred_ls(pin, serial, udp):
    """List stored credentials"""
    if not pin:
        pin = getpass.getpass("PIN: ")

    client = solo.client.find(serial, udp=udp)
    cm = client.cred_mgmt(pin)
    meta = cm.get_metadata()
    existing = meta[CredentialManagement.RESULT.EXISTING_CRED_COUNT]
    if existing == 0:
        print("No resident credentials on this device.")
        return
    rps = cm.enumerate_rps()
    all_creds = {}
    for rp in rps:
        rp_id = rp[CredentialManagement.RESULT.RP]["id"]
        creds = cm.enumerate_creds(rp[CredentialManagement.RESULT.RP_ID_HASH])
        all_creds[rp_id] = creds
    if all_creds:
        print("{:20}{:20}{}".format("Relying Party", "Username", "Credential ID"))
        print("-" * 53)
    for rp_id, creds in all_creds.items():
        for cred in creds:
            user = cred.get(CredentialManagement.RESULT.USER, "")
            cred_id = cred[CredentialManagement.RESULT.CREDENTIAL_ID]["id"]
            cred_id_b64 = base64.b64encode(cred_id).decode("ascii")
            print("{:20}{:20}{}".format(rp_id, user["name"], cred_id_b64))


@click.command(name="rm")
@click.option("--pin", help="PIN for to access key")
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
@click.argument("credential-id")
def cred_rm(pin, credential_id, serial, udp):
    """Remove stored credential"""
    if not pin:
        pin = getpass.getpass("PIN: ")

    client = solo.client.find(serial, udp=udp)
    cm = client.cred_mgmt(pin)
    cred = {"id": base64.b64decode(credential_id), "type": "public-key"}
    cm.delete_cred(cred)


@click.command()
@click.option("--pin", help="PIN for to access key")
@click.option("-s", "--serial", help="Serial number of Solo to use")
@click.option(
    "--udp", is_flag=True, default=False, help="Communicate over UDP with software key"
)
@click.option(
    "--prompt",
    help="Prompt for user",
    default="Touch your authenticator to generate a response...",
    show_default=True,
)
@click.option("--host", default="solo-sign-hash:", help="Choose relying host, must start with 'solo-sign-hash:'")
@click.option("--minisign", is_flag=True, default=False,
              help="Use Minisign-compatible signature (pre-hashed) with EdDSA credential,"
                   " default is to try ES256 signature")
@click.option("--sig-file", default=None, help="Destination file for signature"
                                               " (<filename>.(mini)sig if empty)")
@click.option("--trusted-comment", default=None,
              help="Trusted comment included in global signature (combine with --minisign)"
                   " [default: <time and file name, hashed>]")
@click.option("--untrusted-comment", default="signature created on solokey", show_default=True,
              help="Untrusted comment not included in global signature (combine with --minisign and --sig-file)")
@click.option("--key-id", default=None,
              help="Key ID to write to signature file (8 bytes as HEX) (combine with --minisign and --sig-file) "
                   "[default: <hash of credential ID>]")
@click.argument("credential-id")
@click.argument("filename")
def sign_file(pin, serial, udp, prompt, credential_id, host, filename, sig_file,
              minisign, trusted_comment, untrusted_comment, key_id):
    """Sign the specified file using the given credential-id"""

    # check for PIN
    if not pin:
        pin = getpass.getpass("PIN (leave empty for no PIN): ")
    if not pin:
        pin = None

    dev = solo.client.find(solo_serial=serial, udp=udp)

    credential_id = bytes.fromhex(credential_id)

    dgst = hashlib.blake2b() if minisign else hashlib.sha256()
    with open(filename, "rb") as f:
        while True:
            data = f.read(64 * 1024)
            if not data:
                break
            dgst.update(data)
    print(f"{dgst.hexdigest()}  {filename}")

    if prompt:
        print(prompt)

    if minisign:
        if trusted_comment is None:
            timestamp = int(time.time())
            just_file_name = pathlib.Path(filename).name
            trusted_comment = f"timestamp:{timestamp}\tfile:{just_file_name}\thashed"
            trusted_comment_bytes = trusted_comment.encode()
            if len(trusted_comment_bytes) > 128:
                trusted_comment = f"timestamp:{timestamp}\tfile:<name too long>\thashed"
            trusted_comment_bytes = trusted_comment.encode()
        else:
            trusted_comment_bytes = trusted_comment.encode()

        print(f"Trusted comment: {trusted_comment}")

        try:
            ret = dev.sign_hash(credential_id, dgst.digest(), pin, host, trusted_comment_bytes)
        except CtapError as err:
            if err.code == CtapError.ERR.INVALID_OPTION:
                print("Got CTAP error 0x2C INVALID_OPTION. Are you sure you used an EdDSA credential with Minisign?")
                sys.exit(1)
            elif err.code == CtapError.ERR.INVALID_LENGTH:
                print("Got CTAP error 0x03 INVALID_LENGTH. Are you sure you used an EdDSA credential with Minisign?")
                sys.exit(1)
            elif err.code == CtapError.ERR.INVALID_CREDENTIAL:
                print("Got CTAP error 0x22 INVALID_CREDENTIAL.")
                if host.startswith("solo-sign-hash:"):
                    print(f"Are you sure you created this credential using host '{host}'?")
                else:
                    print("Host should start with 'solo-sign-hash:'")
                sys.exit(1)
            else:
                raise

        file_signature = ret[1]
        if ret[2] is None:
            print("Authenticator does not support Minisign")
            sys.exit(1)
        global_signature = ret[2]

        print(f"File signature (Base64): {base64.b64encode(file_signature).decode()}")
        print(f"Global signature (Base64): {base64.b64encode(global_signature).decode()}")

        if sig_file is not None:
            untrusted_comment_bytes = untrusted_comment.encode()
            if key_id is not None:
                key_id = int(key_id, 16).to_bytes(8, "little")
            else:
                key_id = hashlib.blake2b(credential_id).digest()[:8]
            key_id_hex = f"{int.from_bytes(key_id, 'little'):X}"

            if sig_file == "":
                sig_file = filename + ".minisig"
            with open(sig_file, "wb") as f:
                f.write(b"untrusted comment: ")
                f.write(untrusted_comment_bytes)
                f.write(b"\n")
                f.write(base64.b64encode(b"ED" + key_id + file_signature))
                f.write(b"\ntrusted comment: ")
                f.write(trusted_comment_bytes)
                f.write(b"\n")
                f.write(base64.b64encode(global_signature))
                f.write(b"\n")

            print(f"Signature using key {key_id_hex} written to {sig_file}")

    else:
        try:
            ret = dev.sign_hash(credential_id, dgst.digest(), pin, host)
        except CtapError as err:
            if err.code == CtapError.ERR.INVALID_LENGTH:
                print("Got CTAP error 0x03 INVALID_LENGTH. Are you sure you used an ES256 credential, "
                      "or did you mean to specify --minisign?")
                sys.exit(1)
            elif err.code == CtapError.ERR.INVALID_CREDENTIAL:
                print("Got CTAP error 0x22 INVALID_CREDENTIAL.")
                if host.startswith("solo-sign-hash:"):
                    print(f"Are you sure you created this credential using host '{host}'?")
                else:
                    print("Host should start with 'solo-sign-hash:'")
                sys.exit(1)

        signature = ret[1]

        print(f"Signature (Base64): {base64.b64encode(signature).decode()}")

        if sig_file is not None:
            if sig_file == "":
                sig_file = filename + ".sig"

            with open(sig_file, "wb") as f:
                f.write(signature)

            print(f"Signature written to {sig_file}")


key.add_command(rng)
rng.add_command(hexbytes)
rng.add_command(raw)
rng.add_command(feedkernel)
key.add_command(list_algorithms)
key.add_command(make_credential)
key.add_command(challenge_response)
key.add_command(reset)
key.add_command(update)
key.add_command(probe)
key.add_command(change_pin)
key.add_command(set_pin)
# key.add_command(sha256sum)
# key.add_command(sha512sum)
key.add_command(version)
key.add_command(verify)
key.add_command(wink)
key.add_command(disable_updates)
key.add_command(ping)
key.add_command(keyboard)
key.add_command(cred)
key.add_command(sign_file)
cred.add_command(cred_info)
cred.add_command(cred_ls)
cred.add_command(cred_rm)
