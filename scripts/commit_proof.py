from pathlib import Path
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


PROJECT_ROOT = Path(__file__).resolve().parent.parent
STUDENT_PRIV = PROJECT_ROOT / "student_private.pem"
INSTRUCTOR_PUB = PROJECT_ROOT / "instructor_public.pem"


def load_private_key():
    data = STUDENT_PRIV.read_bytes()
    return serialization.load_pem_private_key(data, password=None, backend=default_backend())


def load_public_key():
    data = INSTRUCTOR_PUB.read_bytes()
    return serialization.load_pem_public_key(data, backend=default_backend())


def sign_message(message: str, private_key) -> bytes:
    # Step 13: RSA-PSS with SHA-256
    msg_bytes = message.encode("utf-8")
    signature = private_key.sign(
        msg_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def main():
    commit_hash = input("Enter commit hash: ").strip()

    priv = load_private_key()
    pub = load_public_key()

    sig = sign_message(commit_hash, priv)
    encrypted_sig = encrypt_with_public_key(sig, pub)

    b64 = base64.b64encode(encrypted_sig).decode("ascii")
    print("\nEncrypted commit signature (single line):")
    print(b64)


if __name__ == "__main__":
    main()
