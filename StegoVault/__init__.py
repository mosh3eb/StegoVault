"""
StegoVault - Advanced Steganography Tool
A powerful, cross-platform tool for hiding files inside images with encryption and advanced features.
"""

__version__ = "2.0.0"
__author__ = "StegoVault Team"

from .core import StegoEngine
from .crypto import CryptoManager
from .cli import CLIInterface
from .archive import ArchiveManager
from .robustness import RobustnessEngine
from .steganalysis import SteganalysisProtection
from .metadata import MetadataManager
from .capacity import CapacityManager

__all__ = [
    'StegoEngine', 
    'CryptoManager', 
    'CLIInterface',
    'ArchiveManager',
    'RobustnessEngine',
    'SteganalysisProtection',
    'MetadataManager',
    'CapacityManager'
]

