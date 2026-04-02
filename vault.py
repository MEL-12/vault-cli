import os
import json
import base64
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_FILE = "vault.enc"
SALT_FILE  = "vault.salt"

# ── Key derivation ──────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,           # 256-bit key
        salt=salt,
        iterations=600_000,  # OWASP 2024 recommendation
    )
    return kdf.derive(password.encode())

# ── Vault I/O ───────────────────────────────────────────────────
def load_or_create_salt() -> bytes:
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt

def load_vault(key: bytes) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "rb") as f:
        raw = f.read()
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext)
    except Exception:
        print("❌  Wrong master password or corrupted vault.")
        exit(1)

def save_vault(key: bytes, data: dict):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, json.dumps(data).encode(), None)
    with open(VAULT_FILE, "wb") as f:
        f.write(nonce + ciphertext)

# ── CLI commands ────────────────────────────────────────────────
def cmd_add(vault, key):
    site  = input("Site/App:   ").strip()
    user  = input("Username:   ").strip()
    pwd   = getpass.getpass("Password:   ")
    notes = input("Notes:      ").strip()
    vault[site] = {"username": user, "password": pwd, "notes": notes}
    save_vault(key, vault)
    print(f"✅  Saved entry for '{site}'")

def cmd_get(vault):
    site = input("Site/App to look up: ").strip()
    entry = vault.get(site)
    if not entry:
        print(f"❌  No entry found for '{site}'")
        return
    print(f"\n  Site:     {site}")
    print(f"  Username: {entry['username']}")
    print(f"  Password: {entry['password']}")
    if entry.get("notes"):
        print(f"  Notes:    {entry['notes']}")
    print()

def cmd_list(vault):
    if not vault:
        print("Vault is empty.")
        return
    print("\nStored sites:")
    for site, e in vault.items():
        print(f"  • {site}  ({e['username']})")
    print()

def cmd_delete(vault, key):
    site = input("Site/App to delete: ").strip()
    if site in vault:
        del vault[site]
        save_vault(key, vault)
        print(f"🗑  Deleted '{site}'")
    else:
        print("Entry not found.")

# ── Entry point ─────────────────────────────────────────────────
def main():
    print("\n🔐  Vault — AES-256 Password Manager\n")
    master = getpass.getpass("Master password: ")
    salt   = load_or_create_salt()
    key    = derive_key(master, salt)
    vault  = load_vault(key)

    COMMANDS = {
        "add": lambda: cmd_add(vault, key),
        "get": lambda: cmd_get(vault),
        "list": lambda: cmd_list(vault),
        "delete": lambda: cmd_delete(vault, key),
        "quit": None,
    }

    while True:
        print("Commands: add | get | list | delete | quit")
        choice = input("> ").strip().lower()
        if choice == "quit":
            break
        fn = COMMANDS.get(choice)
        if fn:
            fn()
        else:
            print("Unknown command.")

if __name__ == "__main__":
    main()