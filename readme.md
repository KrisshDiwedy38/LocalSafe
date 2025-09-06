# LocalSafe - Encrypted File Vault CLI

LocalSafe is a secure command-line tool for encrypting and storing files locally. It provides military-grade encryption with a user-friendly interface, protecting your sensitive files with strong cryptographic primitives and automatic security features.

## 🔒 Security Features

- **AES-256-GCM Encryption**: Authenticated encryption with 256-bit keys
- **Envelope Encryption**: Each file gets a unique encryption key
- **Argon2id Password Hashing**: Memory-hard password hashing resistant to attacks
- **PBKDF2 Key Derivation**: 100,000 iterations with SHA-256
- **Auto-lock Mechanism**: Automatically locks after configurable inactivity
- **Secure Memory Management**: Sensitive data is cleared from memory
- **File Integrity Verification**: SHA-256 checksums detect tampering
- **SQLite with WAL Mode**: Secure metadata storage with atomic operations

## 📋 Requirements

- Python 3.11 or higher
- Required packages:
  - `cryptography>=41.0.0`
  - `argon2-cffi>=23.0.0`

## 🚀 Installation

1. **Clone or download the LocalSafe files**:
   ```bash
   mkdir localsafe
   cd localsafe
   # Copy all .py files to this directory
   ```

2. **Install dependencies**:
   ```bash
   pip install cryptography argon2-cffi
   ```

3. **Make executable** (optional):
   ```bash
   chmod +x localsafe.py
   ```

## 📂 Project Structure

```
localsafe/
├── localsafe.py        # CLI interface and main entry point
├── vault.py            # Vault manager coordinating all operations
├── crypto.py           # AES-256-GCM encryption/decryption
├── auth.py             # Argon2id authentication and key derivation
├── database.py         # SQLite metadata management
├── lock.py             # Auto-lock and session management
├── utils.py            # Security utilities and helpers
├── test_localsafe.py   # Comprehensive unit tests
└── README.md           # This documentation
```

## 🎯 Quick Start

### 1. Initialize a New Vault
```bash
python localsafe.py init
```
You'll be prompted to create a master password. Requirements:
- At least 12 characters
- Must contain: uppercase, lowercase, digit, special character
- Avoid common patterns

### 2. Unlock the Vault
```bash
python localsafe.py unlock
```
Enter your master password to unlock the vault. Auto-lock is enabled by default (5 minutes of inactivity).

### 3. Add Files
```bash
python localsafe.py add document.pdf
python localsafe.py add /path/to/secret-file.txt
```

### 4. List Files
```bash
python localsafe.py list              # Simple list
python localsafe.py list -l           # Detailed information
```

### 5. Retrieve Files
```bash
python localsafe.py get document.pdf                    # Save to current directory
python localsafe.py get document.pdf -o /tmp/doc.pdf    # Save to specific path
```

### 6. Lock the Vault
```bash
python localsafe.py lock
```

## 📖 Command Reference

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `init` | Initialize new vault | `localsafe.py init` |
| `unlock` | Unlock vault with master password | `localsafe.py unlock` |
| `lock` | Lock vault and clear keys from memory | `localsafe.py lock` |
| `add <file>` | Encrypt and store a file | `localsafe.py add document.pdf` |
| `get <filename>` | Decrypt and retrieve a file | `localsafe.py get document.pdf` |
| `list` | List all files in vault | `localsafe.py list -l` |
| `remove <filename>` | Remove file from vault | `localsafe.py remove document.pdf` |
| `status` | Show vault status and statistics | `localsafe.py status` |

### Advanced Commands

| Command | Description | Example |
|---------|-------------|---------|
| `settings` | View/modify vault settings | `localsafe.py settings` |
| `settings --auto-lock-timeout <sec>` | Set auto-lock timeout | `localsafe.py settings --auto-lock-timeout 600` |
| `settings --max-file-size <bytes>` | Set maximum file size | `localsafe.py settings --max-file-size 209715200` |
| `verify` | Check vault and file integrity | `localsafe.py verify` |

### Options

| Option | Description |
|--------|-------------|
| `--vault-dir <path>` | Use custom vault directory |
| `-o, --output <path>` | Specify output path for retrieved files |
| `-l, --long` | Show detailed information in listings |
| `-f, --force` | Skip confirmation prompts |

