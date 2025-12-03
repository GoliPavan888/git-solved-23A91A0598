# app/crypto_utils.py
import base64
import binascii
import pyotp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """Decrypt base64-encrypted seed using RSA/OAEP and return 64-char hex."""
    # 1. Base64 decode
    ciphertext = base64.b64decode(encrypted_seed_b64)

    # 2. RSA/OAEP decrypt with SHA-256
    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 3. Decode bytes to UTF-8
    seed = plaintext_bytes.decode("utf-8")

    # 4. Validate 64-char hex
    if len(seed) != 64 or any(c not in "0123456789abcdef" for c in seed):
        raise ValueError("Decrypted seed is not a 64-character hex string")

    # 5. Return hex seed
    return seed


def generate_totp_code(hex_seed: str) -> str:
    """Generate current 6-digit TOTP code from 64-char hex seed."""
    # 1. Hex -> bytes
    try:
        seed_bytes = binascii.unhexlify(hex_seed)
    except binascii.Error as e:
        raise ValueError("Invalid hex seed") from e

    # 2. Bytes -> base32 string
    base32_seed = base64.b32encode(seed_bytes).decode("ascii")

    # 3. TOTP object (SHA1, 30s, 6 digits)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    # 4. Current code
    return totp.now()
