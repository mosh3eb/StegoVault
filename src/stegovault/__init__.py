"""
StegoVault - Advanced Steganography & Encryption Toolkit

A powerful, cross-platform tool for hiding files inside images with military-grade
encryption and advanced steganographic techniques.

Features:
    - Multiple embedding modes (pixel LSB, frequency domain, histogram preservation)
    - AES-256 encryption with PBKDF2 key derivation
    - Steganalysis detection algorithms
    - Archive embedding support
    - Metadata extraction and privacy tools
    - Multiple user interfaces (CLI, GUI, Web)
    - Netlify serverless deployment ready

Usage:
    from stegovault import StegoEngine
    
    engine = StegoEngine()
    engine.embed_file("secret.txt", "image.png", "stego.png", password="pass")
    engine.extract_file("stego.png", "recovered.txt", password="pass")
"""

__version__ = "2.0.0"
__author__ = "StegoVault Contributors"
__license__ = "MIT"
__url__ = "https://github.com/yourusername/StegoVault"

from .core import StegoEngine
from .crypto import CryptoManager

# Optional imports
try:
    from .archive import ArchiveManager
except ImportError:
    ArchiveManager = None

try:
    from .steganalysis import SteganalysisProtection
except ImportError:
    SteganalysisProtection = None

__all__ = [
    'StegoEngine',
    'CryptoManager',
    'ArchiveManager',
    'SteganalysisProtection',
]

