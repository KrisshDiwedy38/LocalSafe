# 🔒 LocalSafe: Encrypted File Vault

**LocalSafe** is a CLI-based tool for **secure local file storage**.  
It uses **AES-256 encryption** and an **Argon2-protected master password** to lock files, with metadata managed in **SQLite**.  

Designed with privacy in mind, it offers clean **command-line interactions**, built-in **two-factor authentication (2FA)**, and an **auto-lock feature** for enhanced security.  

---

## ✨ Key Features
- 🔐 **Strong Encryption**: Files are encrypted with the industry-standard AES-256 algorithm.  
- 🛡️ **Argon2 Password Protection**: Master password is hashed with Argon2, a memory-hard KDF resistant to brute-force attacks.  
- 🔑 **Two-Factor Authentication (2FA)**: TOTP-based 2FA (Google Authenticator, Authy, etc.) adds an extra layer of protection.  
- 💻 **Command-Line Interface**: Simple CLI powered by argparse for encryption, decryption, and vault management.  
- 📂 **Local Metadata Management**: File metadata (filenames, timestamps, access logs) is stored locally in SQLite — nothing is sent over the network.  
- ⏱️ **Auto-Lock**: Vault automatically locks after a configurable inactivity period, requiring password + 2FA re-entry.  
- ✅ **User-Friendly Feedback**: Clear messages and error handling for a smooth experience.  

---

## 🛠 Tech Stack
- **Core Language**: Python 🐍  
- **Encryption**: `cryptography` (AES-256)  
- **Password Hashing**: `argon2-cffi`  
- **Two-Factor Authentication**: `pyotp` (TOTP)  
- **Database**: SQLite 🗄️  
- **CLI Parsing**: argparse  
- **File System Interaction**: os module  