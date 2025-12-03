from pathlib import Path
import base64
import binascii

import pyotp
from fastapi import FastAPI

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PRIVATE_KEY_PATH = PROJECT_ROOT / "student_private.pem"
PUBLIC_KEY_PATH = PROJECT_ROOT / "student_public.pem"
ENCRYPTED_SEED_PATH = PROJECT_ROOT / "encrypted_seed.txt"
SEED_PATH = PROJECT_ROOT / "data" / "seed.txt"


# ---------- RSA KEY GENERATION ----------

def generate_rsa_keypair(key_size: int = 4096) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)


# ---------- STEP 5: SEED DECRYPTION ----------

def decrypt_seed() -> None:
    """Decrypt encrypted_seed.txt using student_private.pem into data/seed.txt."""
    private_key_pem = PRIVATE_KEY_PATH.read_bytes()
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend(),
    )

    enc_b64 = ENCRYPTED_SEED_PATH.read_text().strip()
    enc_bytes = base64.b64decode(enc_b64)

    seed_bytes = private_key.decrypt(
        enc_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    seed_str = seed_bytes.decode("utf-8")

    # Optional: validate 64-char hex
    if len(seed_str) != 64 or any(c not in "0123456789abcdef" for c in seed_str):
        raise ValueError("Decrypted seed is not a 64-character hex string")

    SEED_PATH.parent.mkdir(parents=True, exist_ok=True)
    SEED_PATH.write_text(seed_str)


def load_seed() -> str:
    return SEED_PATH.read_text().strip()


# ---------- STEP 6: TOTP GENERATION ----------

def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current 6-digit TOTP code from 64-char hex seed.

    Implementation:
    1. Convert hex seed to bytes.
    2. Convert bytes to base32 string.
    3. Create TOTP object (SHA1, 30s, 6 digits).
    4. Return current code.
    """
    # 1. Hex -> bytes
    try:
        seed_bytes = binascii.unhexlify(hex_seed)
    except binascii.Error as e:
        raise ValueError("Invalid hex seed") from e

    # 2. Bytes -> base32 string
    base32_seed = base64.b32encode(seed_bytes).decode("ascii")

    # 3. TOTP object (SHA1, 30s, 6 digits are pyotp defaults)
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    # 4. Current code
    return totp.now()


# ---------- FASTAPI APP ----------

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/otp")
def get_otp():
    """Return current TOTP based on stored hex seed."""
    hex_seed = load_seed()
    code = generate_totp_code(hex_seed)
    return {"otp": code}


if __name__ == "__main__":
    # Optional helper actions when running directly (not in Docker)
    if not PRIVATE_KEY_PATH.exists() or not PUBLIC_KEY_PATH.exists():
        generate_rsa_keypair()
        print("Generated RSA keypair.")

    if ENCRYPTED_SEED_PATH.exists() and not SEED_PATH.exists():
        decrypt_seed()
        print("Decrypted seed into data/seed.txt")
from fastapi import HTTPException
from pydantic import BaseModel
import os
import time


class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


@app.post("/decrypt-seed")
def api_decrypt_seed(body: DecryptSeedRequest):
    try:
        # Overwrite encrypted_seed.txt so your decrypt_seed() can still be reused if needed
        ENCRYPTED_SEED_PATH.write_text(body.encrypted_seed.strip())

        decrypt_seed()  # writes to data/seed.txt and validates hex
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {e}")
@app.get("/generate-2fa")
def generate_2fa():
    if not SEED_PATH.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    hex_seed = load_seed()
    code = generate_totp_code(hex_seed)

    # seconds remaining in current 30s period
    now = int(time.time())
    remaining = 30 - (now % 30)

    return {"code": code, "valid_for": remaining}
class VerifyRequest(BaseModel):
    code: str | None = None


@app.post("/verify-2fa")
def verify_2fa(body: VerifyRequest):
    if not body.code:
        raise HTTPException(status_code=400, detail="Missing code")

    if not SEED_PATH.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    hex_seed = load_seed()
    # Build TOTP in same way as generate_totp_code
    # (reuse it, but need base32 seed)
    try:
        import binascii

        seed_bytes = binascii.unhexlify(hex_seed)
        base32_seed = base64.b32encode(seed_bytes).decode("ascii")
        totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {e}")

    # Verify with ±1 step tolerance
    is_valid = totp.verify(body.code, valid_window=1)

    return {"valid": bool(is_valid)}
