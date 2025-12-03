from pathlib import Path
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PRIVATE_KEY_PATH = PROJECT_ROOT / "student_private.pem"
ENCRYPTED_SEED_PATH = PROJECT_ROOT / "encrypted_seed.txt"
SEED_PATH = PROJECT_ROOT / "data" / "seed.txt"


def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """Step 5: decrypt base64-encrypted seed with RSA/OAEP and return 64-char hex."""
    ciphertext = base64.b64decode(encrypted_seed_b64)

    plaintext_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    seed = plaintext_bytes.decode("utf-8")

    if len(seed) != 64 or any(c not in "0123456789abcdef" for c in seed):
        raise ValueError("Decrypted seed is not a 64-character hex string")

    return seed


def main():
    private_pem = PRIVATE_KEY_PATH.read_bytes()
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend(),
    )

    encrypted_b64 = ENCRYPTED_SEED_PATH.read_text().strip()
    hex_seed = decrypt_seed(encrypted_b64, private_key)

    SEED_PATH.parent.mkdir(parents=True, exist_ok=True)
    SEED_PATH.write_text(hex_seed)
    print("Decrypted seed written to", SEED_PATH)
    print("Seed:", hex_seed)


if __name__ == "__main__":
    main()
