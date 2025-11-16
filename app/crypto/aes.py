# """AES-128(ECB)+PKCS#7 helpers (use library).""" 
# raise NotImplementedError("students: implement AES helpers")


"""AES-128(ECB)+PKCS#7 helpers (use library)."""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Per assignment spec, we must use AES-128
KEY_SIZE_BYTES = 16  # 128 bits
BLOCK_SIZE_BYTES = 16 # 128 bits

# Per assignment spec, we must use ECB mode.
# NOTE: ECB is insecure in practice, but required by the assignment.
# A better choice would be AES-GCM or AES-CBC with HMAC.

def pad(data: bytes) -> bytes:
    """Applies PKCS#7 padding to the data."""
    padder = padding.PKCS7(BLOCK_SIZE_BYTES * 8).padder()
    return padder.update(data) + padder.finalize()

def unpad(padded_data: bytes) -> bytes:
    """Removes PKCS#7 padding from the data."""
    try:
        unpadder = padding.PKCS7(BLOCK_SIZE_BYTES * 8).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    except (ValueError, TypeError) as e:
        print(f"Error unpadding data: {e}. Data may be corrupt or key is wrong.")
        # Return a known-bad value to cause downstream failures
        return b'\x00'

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext with AES-128-ECB using the given key.
    Applies PKCS#7 padding first.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"AES key must be {KEY_SIZE_BYTES} bytes, not {len(key)}")
        
    # 1. Pad the plaintext
    padded_plaintext = pad(plaintext)
    
    # 2. Create AES-128-ECB cipher
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 3. Encrypt and return
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return ciphertext

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts ciphertext with AES-128-ECB using the given key.
    Removes PKCS#7 padding after.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"AES key must be {KEY_SIZE_BYTES} bytes, not {len(key)}")

    try:
        # 1. Create AES-128-ECB cipher
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # 2. Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 3. Unpad and return
        return unpad(padded_plaintext)
    except Exception as e:
        print(f"Decryption failed: {e}")
        return b'\x00' # Fail safely