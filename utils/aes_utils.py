import os
import hashlib
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_group_key(session_keys, private_key):
    """Derives a shared group key."""
    concatenated_keys = b"".join(session_keys) + private_key
    return hashlib.sha256(concatenated_keys).digest()

def encrypt_message(message, key):
    """Encrypts a message using AES CBC mode."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_message = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv.hex(), ciphertext.hex()

def decrypt_message(iv_hex, ciphertext_hex, key):
    """Decrypts an AES CBC encrypted message."""
    iv = bytes.fromhex(iv_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()
