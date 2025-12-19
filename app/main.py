from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import time

from app.crypto_utils import decrypt_seed, generate_totp, verify_totp

DATA_DIR = Path("/data")
SEED_FILE = DATA_DIR / "seed.txt"
PRIVATE_KEY_FILE = Path("/app/student_private.pem")

app = FastAPI()


@app.get("/health")
def health():
    return {"status": "ok"}


class DecryptRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str | None = None


@app.post("/decrypt-seed")
def decrypt_seed_api(body: DecryptRequest):
    try:
        private_key = PRIVATE_KEY_FILE.read_bytes()
        seed = decrypt_seed(body.encrypted_seed.strip(), private_key)
        DATA_DIR.mkdir(exist_ok=True)
        SEED_FILE.write_text(seed)
        return {"status": "ok"}
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed")


@app.get("/generate-2fa")
def generate_2fa():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    seed = SEED_FILE.read_text().strip()
    code = generate_totp(seed)
    remaining = 30 - (int(time.time()) % 30)
    return {"code": code, "valid_for": remaining}


@app.post("/verify-2fa")
def verify_2fa_api(body: VerifyRequest):
    if not body.code:
        raise HTTPException(status_code=400, detail="Missing code")

    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    seed = SEED_FILE.read_text().strip()
    return {"valid": verify_totp(seed, body.code)}
