#  Vault CLI — AES-256 Password Manager

A command-line password manager that stores credentials securely using 
AES-256-GCM encryption and PBKDF2 key derivation. Passwords are saved 
in an encrypted local file and never stored in plain text.


## Features

- AES-256-GCM authenticated encryption
- PBKDF2-SHA256 with 600,000 iterations for key derivation
- Master password is never stored — only used to derive the encryption key
- All data stored locally in an encrypted binary file
- Simple CLI interface with add, get, list and delete commands


## Technologies Used

- Python 3
- `cryptography` library (AES-256-GCM, PBKDF2)
- Git and GitHub for version control


## Project Setup

### Step 1 — Clone the repository
```bash
git clone https://github.com/MEL-12/vault-cli.git
cd vault-cli
```

### Step 2 — Create and activate a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Run the application
```bash
python3 vault.py
```

## How It Works
When you run the app for the first time, it asks for a master password.
This password is never saved anywhere. Instead it is passed through
PBKDF2-SHA256 with a random salt and 600,000 iterations to derive a
256-bit AES encryption key. All your credentials are then encrypted
using AES-256-GCM and saved to a local binary file called `vault.enc`.

Every time you open the vault, your master password is used to
re-derive the same key and decrypt the file. If the wrong password
is entered, decryption fails and nothing is revealed.


## Commands

| Command  | Description                        |
|----------|------------------------------------|
| `add`    | Save a new site, username and password |
| `get`    | Retrieve a stored password         |
| `list`   | List all saved sites               |
| `delete` | Remove a saved entry               |
| `quit`   | Exit the application               |
