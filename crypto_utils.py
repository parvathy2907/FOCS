import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# In a real app, this should be securely stored (env var). 
# For this lab, we generate/store it in a file or hardcode for demo.
# Let's use a key file.
KEY_FILE = 'enc_data/master.key'

def get_or_create_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    return key

MASTER_KEY = get_or_create_key()
cipher_suite = Fernet(MASTER_KEY)

def encrypt_data(data: str) -> bytes:
    """Encrypts string data using AES (Fernet)."""
    return cipher_suite.encrypt(data.encode('utf-8'))

def decrypt_data(token: bytes) -> str:
    """Decrypts bytes token to string."""
    return cipher_suite.decrypt(token).decode('utf-8')

def hash_data(data: str) -> str:
    """Returns SHA-256 hash of data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def hash_password(password: str, salt: str = None) -> (str, str):
    """
    Hashes password using PBKDF2 (SHA-256) with Salt.
    Returns (hashed_password_hex, salt_hex).
    """
    if salt is None:
        salt = os.urandom(16)
    else:
        salt = bytes.fromhex(salt)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode('utf-8'))
    return key.hex(), salt.hex()

def verify_password(stored_password_hex, stored_salt_hex, provided_password):
    """Verifies a password against the stored hash."""
    hashed, _ = hash_password(provided_password, stored_salt_hex)
    return hashed == stored_password_hex
