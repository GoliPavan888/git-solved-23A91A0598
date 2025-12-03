# debug_request_seed_fixed.py
import json
import os
import requests

STUDENT_ID = "23A91A0598"
REPO_WITH = "https://github.com/GoliPavan888/git-solved-23A91A0598.git"
REPO_WITHOUT = "https://github.com/GoliPavan888/git-solved-23A91A0598"

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
PUBKEY_FILE = "student_public.pem"


def read_pub_single(path: str) -> str:
    """Read PEM public key as normal multi-line text."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Public key file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        txt = f.read()
    return txt.replace("\r\n", "\n").replace("\r", "\n")


def try_post(repo_url: str) -> None:
    try:
        pk = read_pub_single(PUBKEY_FILE)
    except Exception as e:
        print("Failed to read public key:", e)
        return

    payload = {
        "student_id": STUDENT_ID,
        "github_repo_url": repo_url,
        "public_key": pk,
    }

    print("\n--- Trying repo_url =", repo_url)
    preview = payload.copy()
    if len(preview["public_key"]) > 120:
        preview["public_key"] = preview["public_key"][:120] + "..."
    print("Payload preview (trimmed):")
    print(json.dumps(preview, indent=2))

    try:
        r = requests.post(API_URL, json=payload, timeout=20)
    except requests.exceptions.RequestException as e:
        print("Network error:", repr(e))
        return

    print("HTTP", r.status_code)
    print("Response headers:")
    for k, v in r.headers.items():
        print(f"{k}: {v}")
    print("Response body:")
    try:
        js = r.json()
        print(json.dumps(js, indent=2))
        if r.status_code == 200 and "encrypted_seed" in js:
            with open("encrypted_seed.txt", "w", encoding="utf-8") as f:
                f.write(js["encrypted_seed"])
            print("Saved encrypted seed to encrypted_seed.txt")
    except ValueError:
        print(r.text)


def main() -> None:
    try_post(REPO_WITH)
    try_post(REPO_WITHOUT)


if __name__ == "__main__":
    main()
