from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def generate_rsa_keypair(key_size: int = 4096) -> None:
    """
    Generate RSA 4096‑bit key pair for student identity and save as PEM files.

    Creates:
      - student_private.pem (PKCS8, no password)
      - student_public.pem  (SubjectPublicKeyInfo)
    """

    # 1. Generate private key (4096 bits, exponent 65537)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend(),
    )

    public_key = private_key.public_key()

    # 2. Serialize private key to PEM (PKCS8, no encryption)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # 3. Serialize public key to PEM (SubjectPublicKeyInfo)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # 4. Write to files in project root
    (PROJECT_ROOT / "student_private.pem").write_bytes(private_pem)
    (PROJECT_ROOT / "student_public.pem").write_bytes(public_pem)


if __name__ == "__main__":
    generate_rsa_keypair()
    print("Generated student_private.pem and student_public.pem")
