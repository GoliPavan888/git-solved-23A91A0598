# scripts/log_2fa_cron.py

from pathlib import Path
from datetime import datetime

from app.main import generate_totp_code  # reuse Step 6 helper


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SEED_PATH = PROJECT_ROOT / "data" / "seed.txt"
LOG_PATH = PROJECT_ROOT / "cron" / "last_code.txt"


def load_seed() -> str:
    return SEED_PATH.read_text().strip()


def main() -> None:
    hex_seed = load_seed()
    code = generate_totp_code(hex_seed)

    timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    line = f"{timestamp} OTP={code}\n"

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(line)


if __name__ == "__main__":
    main()
