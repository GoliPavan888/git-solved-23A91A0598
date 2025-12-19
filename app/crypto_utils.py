import base64
import binascii
import pyotp

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def decrypt_seed(encrypted_seed_b64: str, private_key_pem: bytes) -> str:
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )

    encrypted_bytes = base64.b64decode(encrypted_seed_b64)

    seed_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    seed = seed_bytes.decode("utf-8")

    if len(seed) != 64 or any(c not in "0123456789abcdef" for c in seed):
        raise ValueError("Invalid seed")

    return seed


def generate_totp(hex_seed: str) -> str:
    seed_bytes = binascii.unhexlify(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode()
    totp = pyotp.TOTP(base32_seed)
    return totp.now()


def verify_totp(hex_seed: str, code: str) -> bool:
    seed_bytes = binascii.unhexlify(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode()
    totp = pyotp.TOTP(base32_seed)
    return totp.verify(code, valid_window=1)
