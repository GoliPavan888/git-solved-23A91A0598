import time
from pathlib import Path
import base64
import binascii
import pyotp

SEED_FILE = Path("/data/seed.txt")

if not SEED_FILE.exists():
    print("Seed not found")
    exit(0)

hex_seed = SEED_FILE.read_text().strip()

seed_bytes = binascii.unhexlify(hex_seed)
base32_seed = base64.b32encode(seed_bytes).decode("ascii")

totp = pyotp.TOTP(base32_seed, interval=30, digits=6)
code = totp.now()

print(f"{int(time.time())}: {code}")
