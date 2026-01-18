"""
Encryption and decryption functionality using AES-256-CBC
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from typing import Optional


class CryptoManager:
    """Handles AES-256-CBC encryption and decryption"""
    
    def __init__(self):
        self.algorithm = algorithms.AES
        self.mode = modes.CBC
        self.key_size = 32  # 256 bits
        self.iv_size = 16  # 128 bits
        self.salt_size = 16
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def encrypt(self, data: bytes, password: str):
        """
        Encrypt data using AES-256-CBC
        
        Returns:
            tuple: (encrypted_data, salt, iv)
        """
        # Generate random salt and IV
        salt = os.urandom(self.salt_size)
        iv = os.urandom(self.iv_size)
        
        # Derive key from password
        key = self.derive_key(password, salt)
        
        # Create cipher
        cipher = Cipher(
            self.algorithm(key),
            self.mode(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data to block size (16 bytes for AES)
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length] * pad_length)
        
        # Encrypt
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        return encrypted, salt, iv
    
    def decrypt(self, encrypted_data: bytes, password: str, salt: bytes, iv: bytes) -> bytes:
        """
        Decrypt data using AES-256-CBC
        
        Returns:
            bytes: Decrypted data
        
        Raises:
            ValueError: If decryption fails (wrong password or corrupted data)
        """
        try:
            # Derive key from password
            key = self.derive_key(password, salt)
            
            # Create cipher
            cipher = Cipher(
                self.algorithm(key),
                self.mode(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            pad_length = padded_data[-1]
            if pad_length > 16 or pad_length == 0:
                raise ValueError("Incorrect password or corrupted data")
            
            # Verify padding is valid (all padding bytes should be the same)
            if len(padded_data) < pad_length:
                raise ValueError("Incorrect password or corrupted data")
            
            padding = padded_data[-pad_length:]
            if not all(b == pad_length for b in padding):
                raise ValueError("Incorrect password or corrupted data")
            
            return padded_data[:-pad_length]
        except Exception as e:
            # If decryption fails, it's likely a wrong password
            if "Invalid padding" in str(e) or "Invalid" in str(e):
                raise ValueError("Incorrect password") from e
            raise ValueError(f"Decryption failed: {e}") from e
    
    def hash_data(self, data: bytes) -> bytes:
        """Compute SHA-256 hash of data"""
        return hashlib.sha256(data).digest()

