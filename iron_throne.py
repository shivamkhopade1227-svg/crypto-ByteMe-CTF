from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import sys

# -------------------------------------------------------------------
# Iron Throne (server side)
# -------------------------------------------------------------------

from dragonstone import _PART_B

_PART_A = int.from_bytes(b"targaryen_", "big")

SERVER_PRIVATE_KEY = ec.derive_private_key(
    _PART_A ^ _PART_B,
    ec.SECP256R1()
)

SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key()

NONCE_SIZE = 16


def derive_session_key(client_public_key):
    """
    Derive session key using ECDH + custom mixing + HKDF
    """
    shared_secret = SERVER_PRIVATE_KEY.exchange(
        ec.ECDH(),
        client_public_key
    )

    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    digest.update(b"winter_is_coming")
    mixed_secret = digest.finalize()

    info = (
        b"iron_throne_rules" +
        SERVER_PUBLIC_KEY.public_numbers().x.to_bytes(32, "big")
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashes.Hash(hashes.SHA256()).finalize(),
        info=info
    )

    return hkdf.derive(mixed_secret)


def encrypt_message(key, plaintext):
    """
    AES-GCM encryption (used only during generation)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def derive_fake_key(pub):
    """
    Legacy / deprecated crypto path (red herring)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA1(),
        length=16,
        salt=b"legacy",
        info=b"legacy_handshake"
    )
    return hkdf.derive(b"\x00" * 32)


def export_public_key(pub):
    """
    Export ECC public key coordinates
    """
    numbers = pub.public_numbers()
    return numbers.x, numbers.y


if sys.gettrace():
    exit("Ravens detected a spy.")

if __name__ == "__main__":
    exit("The Iron Throne does not answer directly.")





