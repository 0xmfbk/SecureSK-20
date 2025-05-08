# Requirements: pip install pycryptodome colorama requests argon2-cffi
import hashlib
import hmac
from Crypto.Hash import MD4
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import getpass
import requests
import json
from colorama import init, Fore, Style
import zlib
import base64
try:
    from Crypto.Hash import RIPEMD, Whirlpool
    CRYPTO_HASH_AVAILABLE = True
except ImportError:
    CRYPTO_HASH_AVAILABLE = False

init(autoreset=True)

# Constants
SALT_SIZE = 16  # 16 bytes (128 bits) for salt
AES_KEY_SIZE = 32  # 32 bytes (256 bits) for AES key
HMAC_KEY_SIZE = 32  # 32 bytes (256 bits) for HMAC key

# Modern Banner
BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
███████╗███████╗ ██████╗██╗   ██╗███████╗██████╗ ███████╗██╗  ██╗    ██████╗  ██████╗ 
██╔════╝██╔════╝██╔════╝██║   ██║██╔════╝██╔══██╗██╔════╝██║ ██╔╝    ╚════██╗██╔═████╗
███████╗█████╗  ██║     ██║   ██║█████╗  ██████╔╝███████╗█████╔╝      █████╔╝██║██╔██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══╝  ██╔══██╗╚════██║██╔═██╗     ██╔═══╝ ████╔╝██║
███████║███████╗╚██████╗╚██████╔╝███████╗██║  ██║███████║██║  ██╗    ███████╗╚██████╔╝
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝ 
{Style.RESET_ALL}{Fore.YELLOW}By 0xmfmbk{Style.RESET_ALL}
"""

def generate_salt():
    """
    Generate a random salt for password hashing.

    Returns:
        bytes: Random salt.
    """
    return os.urandom(SALT_SIZE)

def generate_md5(password, salt):
    """Generate MD5 hash."""
    return hashlib.md5(salt + password.encode()).hexdigest()

def generate_sha1(password, salt):
    """Generate SHA-1 hash."""
    return hashlib.sha1(salt + password.encode()).hexdigest()

def generate_sha256(password, salt):
    """Generate SHA-256 hash."""
    return hashlib.sha256(salt + password.encode()).hexdigest()

def generate_sha512(password, salt):
    return hashlib.sha512(salt + password.encode()).hexdigest()

def generate_blake2b(password, salt):
    return hashlib.blake2b(salt + password.encode()).hexdigest()

def generate_ntlm(password):
    """Generate NTLM (NT) hash."""
    password_bytes = password.encode('utf-16le')  # Encode to UTF-16 little-endian for NTLM hash
    return MD4.new(password_bytes).hexdigest()

def generate_argon2(password, salt):
    if not ARGON2_AVAILABLE:
        return f"{Fore.RED}Argon2 not available. Install with: pip install argon2-cffi{Style.RESET_ALL}"
    ph = PasswordHasher()
    # Argon2 does not use salt in the same way, but for demo, we append it
    return ph.hash(password + salt.hex())

def encrypt_data(data, key):
    """
    Encrypt data using AES-256-CBC.

    Args:
        data (str): Data to encrypt.
        key (bytes): AES encryption key.

    Returns:
        tuple: A tuple containing the encrypted data and initialization vector (IV).
    """
    iv = os.urandom(16)  # 16 bytes (128 bits) for IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return encrypted_data, iv

def decrypt_data(encrypted_data, key, iv):
    """
    Decrypt data using AES-256-CBC.

    Args:
        encrypted_data (bytes): Encrypted data.
        key (bytes): AES encryption key.
        iv (bytes): Initialization vector.

    Returns:
        str: Decrypted data.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()

def generate_hmac(data, key):
    """
    Generate HMAC for data integrity.

    Args:
        data (bytes): Data to generate HMAC for.
        key (bytes): HMAC key.

    Returns:
        str: HMAC hexdigest.
    """
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def generate_sha224(password, salt):
    return hashlib.sha224(salt + password.encode()).hexdigest()

def generate_sha384(password, salt):
    return hashlib.sha384(salt + password.encode()).hexdigest()

def generate_sha3_256(password, salt):
    return hashlib.sha3_256(salt + password.encode()).hexdigest()

def generate_blake2s(password, salt):
    return hashlib.blake2s(salt + password.encode()).hexdigest()

def generate_pbkdf2(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()

def generate_scrypt(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()

def generate_crc32(password, salt):
    return format(zlib.crc32(salt + password.encode()), '08x')

def generate_ripemd160(password, salt):
    if CRYPTO_HASH_AVAILABLE:
        h = RIPEMD.new()
        h.update(salt + password.encode())
        return h.hexdigest()
    else:
        return f"{Fore.RED}RIPEMD160 not available. Install with: pip install pycryptodome{Style.RESET_ALL}"

def generate_whirlpool(password, salt):
    if CRYPTO_HASH_AVAILABLE:
        h = Whirlpool.new()
        h.update(salt + password.encode())
        return h.hexdigest()
    else:
        return f"{Fore.RED}Whirlpool not available. Install with: pip install pycryptodome{Style.RESET_ALL}"

def password_strength_checker(password):
    import re
    length = len(password) >= 8
    upper = re.search(r"[A-Z]", password) is not None
    lower = re.search(r"[a-z]", password) is not None
    digit = re.search(r"\d", password) is not None
    special = re.search(r"[^A-Za-z0-9]", password) is not None
    score = sum([length, upper, lower, digit, special])
    if score == 5:
        return "Very Strong"
    elif score == 4:
        return "Strong"
    elif score == 3:
        return "Medium"
    elif score == 2:
        return "Weak"
    else:
        return "Very Weak"

def generate_random_password(length):
    import string, random
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def hash_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        return hashlib.sha256(file_data).hexdigest()
    except Exception:
        return f"{Fore.RED}Could not read or hash the file.{Style.RESET_ALL}"

def display_menu():
    left_options = [
        ("1", "Generate MD5 Hash"),
        ("2", "Generate SHA-1 Hash"),
        ("3", "Generate SHA-224 Hash"),
        ("4", "Generate SHA-256 Hash"),
        ("5", "Generate SHA-384 Hash"),
        ("6", "Generate SHA-512 Hash"),
        ("7", "Generate SHA3-256 Hash"),
        ("8", "Generate BLAKE2b Hash"),
        ("9", "Generate BLAKE2s Hash"),
        ("10", "Generate CRC32 Checksum"),
        ("11", "Generate NTLM (NT) Hash"),
        ("12", "Generate HMAC for Data"),
        ("13", "Generate PBKDF2 Hash"),
        ("14", "Generate Scrypt Hash"),
        ("15", "Base64 Encode"),
        ("16", "Base64 Decode"),
        ("17", "Password Strength Checker"),
    ]
    right_options = [
        ("18", "Random Password Generator"),
        ("19", "File Hashing Tool"),
        ("20", "Encrypt Password (AES-256-CBC)"),
        ("21", "Decrypt Password (AES-256-CBC)"),
        ("22", "Encrypt with DES"),
        ("23", "Decrypt with DES"),
        ("24", "Encrypt with Triple DES"),
        ("25", "Decrypt with Triple DES"),
        ("26", "Encrypt with ChaCha20"),
        ("27", "Decrypt with ChaCha20"),
        ("28", "Encrypt with Fernet"),
        ("29", "Decrypt with Fernet"),
        ("30", "Encrypt with RSA"),
        ("31", "Decrypt with RSA"),
        ("32", "Encrypt with ECC"),
        ("33", "Decrypt with ECC"),
        ("34", "Exit"),
    ]
    print(f"\n{Fore.GREEN}{Style.BRIGHT}Choose an option:{Style.RESET_ALL}")
    if len(left_options) < len(right_options):
        left_options += [('', '')] * (len(right_options) - len(left_options))
    for left, right in zip(left_options, right_options):
        left_str = f"{Fore.BLUE}{left[0]}.{Style.RESET_ALL} {left[1]}" if left[0] else ""
        right_str = f"{Fore.BLUE}{right[0]}.{Style.RESET_ALL} {right[1]}"
        print(f"{left_str:<45} {right_str}")

def show_help(option):
    helps = {
        "1": "MD5: Generates an MD5 hash of your password with a random salt.",
        "2": "SHA-1: Generates a SHA-1 hash of your password with a random salt.",
        "3": "SHA-224: Generates a SHA-224 hash of your password with a random salt.",
        "4": "SHA-256: Generates a SHA-256 hash of your password with a random salt.",
        "5": "SHA-384: Generates a SHA-384 hash of your password with a random salt.",
        "6": "SHA-512: Generates a SHA-512 hash of your password with a random salt.",
        "7": "SHA3-256: Generates a SHA3-256 hash of your password with a random salt.",
        "8": "BLAKE2b: Generates a BLAKE2b hash of your password with a random salt.",
        "9": "BLAKE2s: Generates a BLAKE2s hash of your password with a random salt.",
        "10": "CRC32: Generates a CRC32 checksum of your password.",
        "11": "NTLM: Generates an NTLM (Windows) hash of your password.",
        "12": "HMAC: Generates an HMAC for your password using a random key.",
        "13": "PBKDF2: Generates a PBKDF2 hash of your password with a random salt.",
        "14": "Scrypt: Generates a Scrypt hash of your password with a random salt.",
        "15": "Base64 Encode: Encodes your plaintext in Base64.",
        "16": "Base64 Decode: Decodes Base64-encoded text.",
        "17": "Password Strength Checker: Checks the strength of your password.",
        "18": "Random Password Generator: Generates a random password of a length you choose.",
        "19": "File Hashing Tool: Calculates the hash of a file you specify.",
        "20": "AES-256-CBC Encrypt: Encrypts your password using AES-256-CBC. Shows the key and IV.",
        "21": "AES-256-CBC Decrypt: Decrypts a password. You must provide the AES key, IV, and encrypted password in hex.",
        "22": "Encrypt with DES: Encrypts your plaintext using DES (demo: uses AES). Shows the key and IV.",
        "23": "Decrypt with DES: Decrypts using DES (demo: uses AES). You must provide the key, IV, and encrypted data in hex.",
        "24": "Encrypt with Triple DES: Encrypts your plaintext using Triple DES (demo: uses AES). Shows the key and IV.",
        "25": "Decrypt with Triple DES: Decrypts using Triple DES (demo: uses AES). You must provide the key, IV, and encrypted data in hex.",
        "26": "Encrypt with ChaCha20: Encrypts your plaintext using ChaCha20 (demo: uses AES). Shows the key and IV.",
        "27": "Decrypt with ChaCha20: Decrypts using ChaCha20 (demo: uses AES). You must provide the key, IV, and encrypted data in hex.",
        "28": "Encrypt with Fernet: Encrypts your plaintext using Fernet (demo: uses AES). Shows the key and IV.",
        "29": "Decrypt with Fernet: Decrypts using Fernet (demo: uses AES). You must provide the key, IV, and encrypted data in hex.",
        "30": "Encrypt with RSA: Encrypts your plaintext using RSA (demo: uses AES). Shows the key and IV.",
        "31": "Decrypt with RSA: Decrypts using RSA (demo: uses AES). You must provide the key, IV, and encrypted data in hex.",
        "32": "Encrypt with ECC: Encrypts your plaintext using ECC (demo: uses AES). Shows the key and IV.",
        "33": "Decrypt with ECC: Decrypts using ECC (demo: uses AES). You must provide the key, IV, and encrypted data in hex.",
        "34": "Exit: Exits the program.",
    }
    print(f"{Fore.CYAN}Help: {helps.get(option, 'No help available for this option.')}{Style.RESET_ALL}")

def main():
    print(BANNER)
    salt = generate_salt()
    print(f"\n{Fore.MAGENTA}Generated Salt: {salt.hex()}{Style.RESET_ALL}")
    while True:
        display_menu()
        choice = input(f"\n{Fore.CYAN}Enter your choice (1-34): {Style.RESET_ALL}")
        try:
            show_help(choice)
            password_options = {"1","2","3","4","5","6","7","8","9","10","11","12","13","14","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33"}
            if choice in password_options:
                password = getpass.getpass(f"{Fore.YELLOW}Enter password/plaintext: {Style.RESET_ALL}")
            if choice == "1":
                print(f"\n{Fore.YELLOW}<=== MD5 Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'MD5')}")
            elif choice == "2":
                print(f"\n{Fore.YELLOW}<=== SHA-1 Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'SHA-1')}")
            elif choice == "3":
                print(f"\n{Fore.YELLOW}<=== SHA-224 Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'SHA-224')}")
            elif choice == "4":
                print(f"\n{Fore.YELLOW}<=== SHA-256 Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'SHA-256')}")
            elif choice == "5":
                print(f"\n{Fore.YELLOW}<=== SHA-384 Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'SHA-384')}")
            elif choice == "6":
                print(f"\n{Fore.YELLOW}<=== SHA-512 Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'SHA-512')}")
            elif choice == "7":
                print(f"\n{Fore.YELLOW}<=== SHA3-256 Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'SHA3-256')}")
            elif choice == "8":
                print(f"\n{Fore.YELLOW}<=== BLAKE2b Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'BLAKE2b')}")
            elif choice == "9":
                print(f"\n{Fore.YELLOW}<=== BLAKE2s Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'BLAKE2s')}")
            elif choice == "10":
                print(f"\n{Fore.YELLOW}<=== CRC32 Checksum ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'CRC32')}")
            elif choice == "11":
                print(f"\n{Fore.YELLOW}<=== NTLM (NT) Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'NTLM')}")
            elif choice == "12":
                hmac_key = os.urandom(HMAC_KEY_SIZE)
                print(f"\n{Fore.CYAN}Generated HMAC Key: {hmac_key.hex()}{Style.RESET_ALL}")
                hmac_value = generate_hmac(password.encode(), hmac_key)
                print(f"\n{Fore.YELLOW}<=== HMAC for Password ===>{Style.RESET_ALL}\n{hmac_value}")
            elif choice == "13":
                print(f"\n{Fore.YELLOW}<=== PBKDF2 Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'PBKDF2')}")
            elif choice == "14":
                print(f"\n{Fore.YELLOW}<=== Scrypt Hash ===>{Style.RESET_ALL}\n{handle_hashing(password, salt, 'Scrypt')}")
            elif choice == "15":
                plaintext = input(f"{Fore.YELLOW}Enter text to encode (Base64): {Style.RESET_ALL}")
                base64_encoded = base64.b64encode(plaintext.encode()).decode()
                print(f"{Fore.CYAN}Base64 Encoded: {base64_encoded}{Style.RESET_ALL}")
            elif choice == "16":
                # Base64 Decode
                encoded_text = input(f"{Fore.YELLOW}Enter Base64 encoded text: {Style.RESET_ALL}")
                try:
                    base64_decoded = base64.b64decode(encoded_text).decode()
                    print(f"{Fore.CYAN}Base64 Decoded: {base64_decoded}{Style.RESET_ALL}")
                except Exception:
                    print(f"{Fore.RED}Invalid Base64 input.{Style.RESET_ALL}")
            elif choice == "17":
                strength = password_strength_checker(password)
                print(f"{Fore.CYAN}Password Strength: {strength}{Style.RESET_ALL}")
            elif choice == "18":
                length = int(input(f"{Fore.YELLOW}Enter the desired length of the password: {Style.RESET_ALL}"))
                password = generate_random_password(length)
                print(f"{Fore.CYAN}Generated Password: {password}{Style.RESET_ALL}")
            elif choice == "19":
                file_path = input(f"{Fore.YELLOW}Enter the path to the file: {Style.RESET_ALL}")
                print(f"{Fore.CYAN}Hashing file...{Style.RESET_ALL}")
                hash_value = hash_file(file_path)
                print(f"{Fore.GREEN}File Hash: {hash_value}{Style.RESET_ALL}")
            elif choice == "20":
                aes_key = os.urandom(AES_KEY_SIZE)
                print(f"\n{Fore.CYAN}Generated AES Key: {aes_key.hex()}{Style.RESET_ALL}")
                encrypted_password, iv = encrypt_data(password, aes_key)
                print(f"\n{Fore.YELLOW}<=== Encrypted Password (AES-256-CBC) ===>{Style.RESET_ALL}\n{encrypted_password.hex()}")
                print(f"{Fore.YELLOW}<=== Initialization Vector (IV) ===>{Style.RESET_ALL}\n{iv.hex()}")
            elif choice == "21":
                aes_key_hex = input(f"{Fore.YELLOW}Enter AES Key (hex): {Style.RESET_ALL}")
                iv_hex = input(f"{Fore.YELLOW}Enter Initialization Vector (IV) (hex): {Style.RESET_ALL}")
                encrypted_password_hex = input(f"{Fore.YELLOW}Enter Encrypted Password (hex): {Style.RESET_ALL}")
                try:
                    aes_key = bytes.fromhex(aes_key_hex)
                    iv = bytes.fromhex(iv_hex)
                    encrypted_password = bytes.fromhex(encrypted_password_hex)
                    decrypted_password = decrypt_data(encrypted_password, aes_key, iv)
                    print(f"\n{Fore.GREEN}<=== Decrypted Password (AES-256-CBC) ===>{Style.RESET_ALL}\n{decrypted_password}")
                except Exception:
                    print(f"\n{Fore.RED}An error occurred while decrypting. Please check your input values.{Style.RESET_ALL}")
            elif choice == "22":
                # DES Encrypt (demo: uses AES)
                aes_key = os.urandom(AES_KEY_SIZE)
                print(f"{Fore.CYAN}Generated DES Key: {aes_key.hex()}{Style.RESET_ALL}")
                encrypted_password, iv = encrypt_data(password, aes_key)
                print(f"{Fore.YELLOW}<=== Encrypted Password (DES) ===>{Style.RESET_ALL}\n{encrypted_password.hex()}")
                print(f"{Fore.YELLOW}<=== Initialization Vector (IV) ===>{Style.RESET_ALL}\n{iv.hex()}")
            elif choice == "23":
                # DES Decrypt (demo: uses AES)
                des_key_hex = input(f"{Fore.YELLOW}Enter DES Key (hex): {Style.RESET_ALL}")
                iv_hex = input(f"{Fore.YELLOW}Enter Initialization Vector (IV) (hex): {Style.RESET_ALL}")
                encrypted_password_hex = input(f"{Fore.YELLOW}Enter Encrypted Password (hex): {Style.RESET_ALL}")
                try:
                    des_key = bytes.fromhex(des_key_hex)
                    iv = bytes.fromhex(iv_hex)
                    encrypted_password = bytes.fromhex(encrypted_password_hex)
                    decrypted_password = decrypt_data(encrypted_password, des_key, iv)
                    print(f"\n{Fore.GREEN}<=== Decrypted Password (DES) ===>{Style.RESET_ALL}\n{decrypted_password}")
                except Exception:
                    print(f"\n{Fore.RED}An error occurred while decrypting. Please check your input values.{Style.RESET_ALL}")
            elif choice == "24":
                # Triple DES Encrypt (demo: uses AES)
                aes_key = os.urandom(AES_KEY_SIZE)
                print(f"{Fore.CYAN}Generated Triple DES Key: {aes_key.hex()}{Style.RESET_ALL}")
                encrypted_password, iv = encrypt_data(password, aes_key)
                print(f"{Fore.YELLOW}<=== Encrypted Password (Triple DES) ===>{Style.RESET_ALL}\n{encrypted_password.hex()}")
                print(f"{Fore.YELLOW}<=== Initialization Vector (IV) ===>{Style.RESET_ALL}\n{iv.hex()}")
            elif choice == "25":
                # Triple DES Decrypt (demo: uses AES)
                tdes_key_hex = input(f"{Fore.YELLOW}Enter Triple DES Key (hex): {Style.RESET_ALL}")
                iv_hex = input(f"{Fore.YELLOW}Enter Initialization Vector (IV) (hex): {Style.RESET_ALL}")
                encrypted_password_hex = input(f"{Fore.YELLOW}Enter Encrypted Password (hex): {Style.RESET_ALL}")
                try:
                    tdes_key = bytes.fromhex(tdes_key_hex)
                    iv = bytes.fromhex(iv_hex)
                    encrypted_password = bytes.fromhex(encrypted_password_hex)
                    decrypted_password = decrypt_data(encrypted_password, tdes_key, iv)
                    print(f"\n{Fore.GREEN}<=== Decrypted Password (Triple DES) ===>{Style.RESET_ALL}\n{decrypted_password}")
                except Exception:
                    print(f"\n{Fore.RED}An error occurred while decrypting. Please check your input values.{Style.RESET_ALL}")
            elif choice == "26":
                # ChaCha20 Encrypt (demo: uses AES)
                aes_key = os.urandom(AES_KEY_SIZE)
                print(f"{Fore.CYAN}Generated ChaCha20 Key: {aes_key.hex()}{Style.RESET_ALL}")
                encrypted_password, iv = encrypt_data(password, aes_key)
                print(f"{Fore.YELLOW}<=== Encrypted Password (ChaCha20) ===>{Style.RESET_ALL}\n{encrypted_password.hex()}")
                print(f"{Fore.YELLOW}<=== Initialization Vector (IV) ===>{Style.RESET_ALL}\n{iv.hex()}")
            elif choice == "27":
                # ChaCha20 Decrypt (demo: uses AES)
                chacha_key_hex = input(f"{Fore.YELLOW}Enter ChaCha20 Key (hex): {Style.RESET_ALL}")
                iv_hex = input(f"{Fore.YELLOW}Enter Initialization Vector (IV) (hex): {Style.RESET_ALL}")
                encrypted_password_hex = input(f"{Fore.YELLOW}Enter Encrypted Password (hex): {Style.RESET_ALL}")
                try:
                    chacha_key = bytes.fromhex(chacha_key_hex)
                    iv = bytes.fromhex(iv_hex)
                    encrypted_password = bytes.fromhex(encrypted_password_hex)
                    decrypted_password = decrypt_data(encrypted_password, chacha_key, iv)
                    print(f"\n{Fore.GREEN}<=== Decrypted Password (ChaCha20) ===>{Style.RESET_ALL}\n{decrypted_password}")
                except Exception:
                    print(f"\n{Fore.RED}An error occurred while decrypting. Please check your input values.{Style.RESET_ALL}")
            elif choice == "28":
                # Fernet Encrypt (demo: uses AES)
                aes_key = os.urandom(AES_KEY_SIZE)
                print(f"{Fore.CYAN}Generated Fernet Key: {aes_key.hex()}{Style.RESET_ALL}")
                encrypted_password, iv = encrypt_data(password, aes_key)
                print(f"{Fore.YELLOW}<=== Encrypted Password (Fernet) ===>{Style.RESET_ALL}\n{encrypted_password.hex()}")
                print(f"{Fore.YELLOW}<=== Initialization Vector (IV) ===>{Style.RESET_ALL}\n{iv.hex()}")
            elif choice == "29":
                # Fernet Decrypt (demo: uses AES)
                fernet_key_hex = input(f"{Fore.YELLOW}Enter Fernet Key (hex): {Style.RESET_ALL}")
                iv_hex = input(f"{Fore.YELLOW}Enter Initialization Vector (IV) (hex): {Style.RESET_ALL}")
                encrypted_password_hex = input(f"{Fore.YELLOW}Enter Encrypted Password (hex): {Style.RESET_ALL}")
                try:
                    fernet_key = bytes.fromhex(fernet_key_hex)
                    iv = bytes.fromhex(iv_hex)
                    encrypted_password = bytes.fromhex(encrypted_password_hex)
                    decrypted_password = decrypt_data(encrypted_password, fernet_key, iv)
                    print(f"\n{Fore.GREEN}<=== Decrypted Password (Fernet) ===>{Style.RESET_ALL}\n{decrypted_password}")
                except Exception:
                    print(f"\n{Fore.RED}An error occurred while decrypting. Please check your input values.{Style.RESET_ALL}")
            elif choice == "30":
                # RSA Encrypt (demo: uses AES)
                aes_key = os.urandom(AES_KEY_SIZE)
                print(f"{Fore.CYAN}Generated RSA Key: {aes_key.hex()}{Style.RESET_ALL}")
                encrypted_password, iv = encrypt_data(password, aes_key)
                print(f"{Fore.YELLOW}<=== Encrypted Password (RSA) ===>{Style.RESET_ALL}\n{encrypted_password.hex()}")
                print(f"{Fore.YELLOW}<=== Initialization Vector (IV) ===>{Style.RESET_ALL}\n{iv.hex()}")
            elif choice == "31":
                # RSA Decrypt (demo: uses AES)
                rsa_key_hex = input(f"{Fore.YELLOW}Enter RSA Key (hex): {Style.RESET_ALL}")
                iv_hex = input(f"{Fore.YELLOW}Enter Initialization Vector (IV) (hex): {Style.RESET_ALL}")
                encrypted_password_hex = input(f"{Fore.YELLOW}Enter Encrypted Password (hex): {Style.RESET_ALL}")
                try:
                    rsa_key = bytes.fromhex(rsa_key_hex)
                    iv = bytes.fromhex(iv_hex)
                    encrypted_password = bytes.fromhex(encrypted_password_hex)
                    decrypted_password = decrypt_data(encrypted_password, rsa_key, iv)
                    print(f"\n{Fore.GREEN}<=== Decrypted Password (RSA) ===>{Style.RESET_ALL}\n{decrypted_password}")
                except Exception:
                    print(f"\n{Fore.RED}An error occurred while decrypting. Please check your input values.{Style.RESET_ALL}")
            elif choice == "32":
                # ECC Encrypt (demo: uses AES)
                aes_key = os.urandom(AES_KEY_SIZE)
                print(f"{Fore.CYAN}Generated ECC Key: {aes_key.hex()}{Style.RESET_ALL}")
                encrypted_password, iv = encrypt_data(password, aes_key)
                print(f"{Fore.YELLOW}<=== Encrypted Password (ECC) ===>{Style.RESET_ALL}\n{encrypted_password.hex()}")
                print(f"{Fore.YELLOW}<=== Initialization Vector (IV) ===>{Style.RESET_ALL}\n{iv.hex()}")
            elif choice == "33":
                # ECC Decrypt (demo: uses AES)
                ecc_key_hex = input(f"{Fore.YELLOW}Enter ECC Key (hex): {Style.RESET_ALL}")
                iv_hex = input(f"{Fore.YELLOW}Enter Initialization Vector (IV) (hex): {Style.RESET_ALL}")
                encrypted_password_hex = input(f"{Fore.YELLOW}Enter Encrypted Password (hex): {Style.RESET_ALL}")
                try:
                    ecc_key = bytes.fromhex(ecc_key_hex)
                    iv = bytes.fromhex(iv_hex)
                    encrypted_password = bytes.fromhex(encrypted_password_hex)
                    decrypted_password = decrypt_data(encrypted_password, ecc_key, iv)
                    print(f"\n{Fore.GREEN}<=== Decrypted Password (ECC) ===>{Style.RESET_ALL}\n{decrypted_password}")
                except Exception:
                    print(f"\n{Fore.RED}An error occurred while decrypting. Please check your input values.{Style.RESET_ALL}")
            elif choice == "34":
                print(f"\n{Fore.CYAN}Exiting the program. Goodbye!{Style.RESET_ALL}")
                break
            else:
                print(f"\n{Fore.RED}Invalid choice. Please select a valid option (1-34).{Style.RESET_ALL}")
        except Exception:
            print(f"\n{Fore.RED}An unexpected error occurred. Please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()