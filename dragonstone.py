from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# -------------------------------------------------------------------
# Dragonstone side (client)
# -------------------------------------------------------------------

_PART_B = int.from_bytes(b"static_key", "big")

client_private_key = ec.generate_private_key(ec.SECP256R1())
client_public_key = client_private_key.public_key()


def derive_session_key(server_public_key):
    """
    Correct handshake path (ECDH + HKDF)
    """
    shared_secret = client_private_key.exchange(
        ec.ECDH(),
        server_public_key
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"house_targaryen",
        info=b"dragon_handshake_v1"
    )

    return hkdf.derive(shared_secret)


def derive_legacy_key(server_public_key):
    """
    Deprecated / legacy handshake (red herring, never used)
    """
    dummy_secret = client_private_key.exchange(
        ec.ECDH(),
        server_public_key
    )

    hkdf = HKDF(
        algorithm=hashes.SHA1(),
        length=16,
        salt=b"legacy_house",
        info=b"dragon_handshake_v0"
    )

    return hkdf.derive(dummy_secret)


def export_public_key(pub):
    """
    Export ECC public key coordinates
    """
    numbers = pub.public_numbers()
    return numbers.x, numbers.y


if __name__ == "__main__":
    exit("Dragonstone is silent.")

