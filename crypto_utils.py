from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import os

# ===================== Constants =====================
KEY_LENGTH = 32               # AES-256 requires a 32-byte key
SALT_LENGTH = 16              # 128-bit salt
IV_LENGTH = 16                # AES block size (128-bit)
PBKDF2_ITERATIONS = 100_000   # Number of iterations for PBKDF2

# ===================== Padding Utilities =====================
def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

# ===================== Key Derivation =====================
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit AES key from the password and salt using PBKDF2 with HMAC-SHA256.
    """
    return PBKDF2(password.encode(), salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

# ===================== File Encryption =====================
def encrypt_file(file_path: str, encrypted_path: str, password: str):
    """
    Encrypts a file using AES-256 (CBC mode) with a password.
    """
    salt = get_random_bytes(SALT_LENGTH)
    iv = get_random_bytes(IV_LENGTH)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext))

    with open(encrypted_path, 'wb') as f:
        f.write(salt + iv + ciphertext)  # Save salt + IV + ciphertext

# ===================== File Decryption =====================
def decrypt_file(encrypted_path: str, output_path: str, password: str):
    """
    Decrypts a file that was encrypted using AES-256 (CBC mode) with a password.
    """
    with open(encrypted_path, 'rb') as f:
        salt = f.read(SALT_LENGTH)
        iv = f.read(IV_LENGTH)
        ciphertext = f.read()

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    with open(output_path, 'wb') as f:
        f.write(plaintext)
