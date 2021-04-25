import struct

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from fido2.attestation import Attestation
from fido2.ctap2 import CTAP2, CredentialManagement
from fido2.hid import CTAPHID
from fido2.utils import hmac_sha256
from fido2.webauthn import PublicKeyCredentialCreationOptions

from solo import helpers


# Base class
# Currently some methods are implemented here since they are the same in both devices.
class SoloClient:
    def __init__(
        self,
    ):
        self.origin = "https://example.org"
        self.host = "example.org"
        self.user_id = b"they"
        self.do_reboot = True

    def set_reboot(self, val):
        """option to reboot after programming"""
        self.do_reboot = val

    def reboot(
        self,
    ):
        pass

    def find_device(self, dev=None, solo_serial=None):
        pass

    def get_current_hid_device(
        self,
    ):
        """Return current device class for CTAPHID interface if available."""
        pass

    def get_current_fido_client(
        self,
    ):
        """Return current fido2 client if available."""
        pass

    def send_data_hid(self, cmd, data):
        if not isinstance(data, bytes):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        with helpers.Timeout(1.0) as event:
            return self.get_current_hid_device().call(cmd, data, event)

    def bootloader_version(
        self,
    ):
        pass

    def solo_version(
        self,
    ):
        pass

    def get_rng(self, num=0):
        pass

    def wink(
        self,
    ):
        self.send_data_hid(CTAPHID.WINK, b"")

    def ping(self, data="pong"):
        return self.send_data_hid(CTAPHID.PING, data)

    def reset(
        self,
    ):
        CTAP2(self.get_current_hid_device()).reset()

    def change_pin(self, old_pin, new_pin):
        client = self.get_current_fido_client()
        client.client_pin.change_pin(old_pin, new_pin)

    def set_pin(self, new_pin):
        client = self.get_current_fido_client()
        client.client_pin.set_pin(new_pin)

    def make_credential(self, pin=None):
        client = self.get_current_fido_client()
        rp = {"id": self.host, "name": "example site"}
        user = {"id": self.user_id, "name": "example user"}
        challenge = b"Y2hhbGxlbmdl"
        options = PublicKeyCredentialCreationOptions(
            rp,
            user,
            challenge,
            [{"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}],
        )
        result = client.make_credential(options, pin=pin)
        attest = result.attestation_object
        data = result.client_data
        try:
            attest.verify(data.hash)
        except AttributeError:
            verifier = Attestation.for_type(attest.fmt)
            verifier().verify(attest.att_statement, attest.auth_data, data.hash)
        print("Register valid")
        x5c = attest.att_statement["x5c"][0]
        cert = x509.load_der_x509_certificate(x5c, default_backend())

        return cert

    def cred_mgmt(self, pin):
        client = self.get_current_fido_client()
        token = client.client_pin.get_pin_token(pin)
        ctap2 = CTAP2(self.get_current_hid_device())
        return CredentialManagement(ctap2, client.client_pin.protocol, token)

    def enter_solo_bootloader(
        self,
    ):
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the bootloader
        so it can be reprogrammed
        """
        pass

    def enter_bootloader_or_die(self):
        pass

    def is_solo_bootloader(
        self,
    ):
        """For now, solo bootloader could be the NXP bootrom on Solo v2."""
        pass

    def program_kbd(self, cmd):
        ctap2 = CTAP2(self.get_current_hid_device())
        return ctap2.send_cbor(0x51, cmd)

    def sign_hash(self, credential_id, dgst, pin):
        ctap2 = CTAP2(self.get_current_hid_device())
        client = self.get_current_fido_client()
        if pin:
            pin_token = client.client_pin.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, dgst)[:16]
            return ctap2.send_cbor(
                0x50,
                {1: dgst, 2: {"id": credential_id, "type": "public-key"}, 3: pin_auth},
            )
        else:
            return ctap2.send_cbor(
                0x50, {1: dgst, 2: {"id": credential_id, "type": "public-key"}}
            )

    def program_file(self, name):
        pass
