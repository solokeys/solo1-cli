import click
from ecdsa import SigningKey, NIST256p
from ecdsa.util import randrange_from_seed__trytryagain

# TODO: move this to solo.operations


@click.command()
@click.option("--input-seed-file")
@click.argument("output_pem_file")
def genkey(input_seed_file, output_pem_file):
    """Generates key par that can be used for Solo signed firmware updates.

    \b
    * Generates NIST P256 keypair.
    * Public key must be copied into correct source location in solo bootloader
    * The private key can be used for signing updates.
    * You may optionally supply a file to seed the RNG for key generating.
    """

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

    print("Public key in various formats:")
    print()
    print([c for c in vk.to_string()])
    print()
    print("".join(["%02x" % c for c in vk.to_string()]))
    print()
    print('"\\x' + "\\x".join(["%02x" % c for c in vk.to_string()]) + '"')
    print()
