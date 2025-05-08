# SecureSK-20 🔐

**SecureSK-20** is your all-in-one, modern terminal toolkit for secure password hashing, encryption, decryption, and file integrity. Fast, flexible, and perfect for cybersecurity, IT, and privacy enthusiasts! 🚀

---

## ✨ Features
- **Hashing:** MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b, BLAKE2s, CRC32, NTLM
- **HMAC, PBKDF2, Scrypt**
- **Base64** encoding/decoding
- **Password tools:** Strength checker, random password generator
- **File hashing** for integrity
- **Encryption/Decryption:** AES, DES, Triple DES, ChaCha20, Fernet, RSA, ECC (with AES as demo placeholder)
- **Colorful, modern terminal UI**
- **Secure password input**

---

## ⚡ Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/SecureSK-20.git
   cd SecureSK-20
   ```

2. **(Recommended) Create and activate a Python virtual environment:**
   - Create a virtual environment:
     ```bash
     python3 -m venv venv
     ```
   - Activate the virtual environment:
     - On **Windows**:
       ```bash
       venv\Scripts\activate
       ```
     - On **macOS/Linux**:
       ```bash
       source venv/bin/activate
       ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the tool:**
   ```bash
   python SecureSK-20.py
   ```

To deactivate the virtual environment when done, simply run:
```bash
deactivate
```

---

## 🛠️ Usage

Run the tool from your terminal:
```bash
python SecureSK-20.py
```

- Enter the number of the desired operation and follow the prompts.
- Password/secret input is hidden for security (except for Base64 encoding, which uses visible input).

---

## 📋 Menu Overview

| Option | Description |
|--------|-------------|
| 1      | Generate MD5 Hash |
| 2      | Generate SHA-1 Hash |
| 3      | Generate SHA-224 Hash |
| 4      | Generate SHA-256 Hash |
| 5      | Generate SHA-384 Hash |
| 6      | Generate SHA-512 Hash |
| 7      | Generate SHA3-256 Hash |
| 8      | Generate BLAKE2b Hash |
| 9      | Generate BLAKE2s Hash |
| 10     | Generate CRC32 Checksum |
| 11     | Generate NTLM (NT) Hash |
| 12     | Generate HMAC for Data |
| 13     | Generate PBKDF2 Hash |
| 14     | Generate Scrypt Hash |
| 15     | Base64 Encode |
| 16     | Base64 Decode |
| 17     | Password Strength Checker |
| 18     | Random Password Generator |
| 19     | File Hashing Tool |
| 20     | Encrypt Password (AES-256-CBC) |
| 21     | Decrypt Password (AES-256-CBC) |
| 22     | Encrypt with DES |
| 23     | Decrypt with DES |
| 24     | Encrypt with Triple DES |
| 25     | Decrypt with Triple DES |
| 26     | Encrypt with ChaCha20 |
| 27     | Decrypt with ChaCha20 |
| 28     | Encrypt with Fernet |
| 29     | Decrypt with Fernet |
| 30     | Encrypt with RSA |
| 31     | Decrypt with RSA |
| 32     | Encrypt with ECC |
| 33     | Decrypt with ECC |
| 34     | Exit |

---

## 📦 Requirements
- Python 3.7+
- `pycryptodome`
- `colorama`
- `requests`
- `argon2-cffi`

Install all dependencies with:
```bash
pip install -r requirements.txt
```

---

## 🔒 Security Notes
- Passwords are never displayed in the terminal (except for Base64 encoding, which uses visible input).
- All cryptographic operations use secure random salts and keys where applicable.
- For demo purposes, some algorithms (DES, Triple DES, ChaCha20, Fernet, RSA, ECC) use AES as a placeholder. For production use, replace with real implementations.

---

## 🤝 Contributing
Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request on GitHub.

---

## 📄 License
This project is licensed under the MIT License.

---

**Author:** 0xmfmbk 
