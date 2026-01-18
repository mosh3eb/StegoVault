"""
StegoVault - Advanced Steganography Tool
A powerful, cross-platform tool for hiding files inside images with encryption and advanced features.
"""

__version__ = "1.0.0"
__author__ = "StegoVault Team"

from .core import StegoEngine
from .crypto import CryptoManager
from .cli import CLIInterface

__all__ = ['StegoEngine', 'CryptoManager', 'CLIInterface']

