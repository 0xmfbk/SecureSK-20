# SecureHashPro

SecureHashPro is a powerful, modern, and user-friendly terminal tool for hashing, encryption, decryption, password management, and file integrity. It supports a wide range of cryptographic algorithms and utilities, making it ideal for cybersecurity professionals, students, and enthusiasts.

## Features
- Multiple hash algorithms: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE2b, BLAKE2s, CRC32, NTLM
- HMAC, PBKDF2, Scrypt
- Base64 encoding/decoding
- Password strength checker and random password generator
- File hashing tool
- Symmetric and asymmetric encryption/decryption (AES, DES, Triple DES, ChaCha20, Fernet, RSA, ECC)
- Colorful, modern terminal UI
- Secure password input

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/SecureHashPro.git
   cd SecureHashPro
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the tool from your terminal:
```bash
python SecureHashPro.py
```

You will be presented with a menu of options. Enter the number of the desired operation and follow the prompts. For password or plaintext input, your entry will be hidden for security (except for Base64 encoding, which uses visible input).

## Menu Options

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

## Requirements
- Python 3.7+
- See `requirements.txt` for all dependencies:
  - pycryptodome
  - colorama
  - requests
  - argon2-cffi

## Security Notes
- Passwords are never displayed in the terminal (except for Base64 encoding, which uses visible input).
- All cryptographic operations use secure random salts and keys where applicable.
- For demo purposes, some algorithms (DES, Triple DES, ChaCha20, Fernet, RSA, ECC) use AES as a placeholder. For production use, replace with real implementations.

## Contributing
Contributions, bug reports, and feature requests are welcome! Please open an issue or submit a pull request on GitHub.

## License
This project is licensed under the MIT License.

---

**Author:** 0xmfmbk 
