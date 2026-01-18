"""
Custom exception classes for StegoVault
"""


class StegoVaultError(Exception):
    """Base exception for StegoVault"""
    pass


class StegoImageError(StegoVaultError):
    """Error related to stego image processing"""
    pass


class EncryptionError(StegoVaultError):
    """Error related to encryption/decryption"""
    pass


class ExtractionError(StegoVaultError):
    """Error during file extraction"""
    pass


class EmbeddingError(StegoVaultError):
    """Error during file embedding"""
    pass

