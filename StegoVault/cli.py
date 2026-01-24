"""
CLI interface with colors and formatting
"""

import os
import getpass
import sys
from typing import Optional, Dict


class CLIInterface:
    """Command-line interface with colored output"""
    
    COLORS = {
        'HEADER': '\033[95m',
        'OKBLUE': '\033[94m',
        'OKCYAN': '\033[96m',
        'OKGREEN': '\033[92m',
        'WARNING': '\033[93m',
        'FAIL': '\033[91m',
        'ENDC': '\033[0m',
        'BOLD': '\033[1m',
        'UNDERLINE': '\033[4m',
    }
    
    def __init__(self, use_colors: bool = None):
        """Initialize CLI interface"""
        if use_colors is None:
            self.use_colors = sys.stdout.isatty() and os.getenv('TERM') != 'dumb'
        else:
            self.use_colors = use_colors

    def print_banner(self):
        """Print a StegoVault banner for an attractive CLI entry."""
        title = "StegoVault"
        subtitle = "Advanced Steganography & Privacy Toolkit"
        line = "═" * 60
        if self.use_colors:
            print(self._colorize(f"\n{line}", 'OKCYAN'))
            print(self._colorize(f"  ███████╗████████╗███████╗ ██████╗  █████╗ ██╗   ██╗ █████╗ ██╗   ██╗", 'OKBLUE'))
            print(self._colorize(f"  ██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝", 'OKBLUE'))
            print(self._colorize(f"  ███████╗   ██║   █████╗  ██║  ███╗███████║██║   ██║███████║ ╚████╔╝ ", 'OKBLUE'))
            print(self._colorize(f"  ╚════██║   ██║   ██╔══╝  ██║   ██║██╔══██║╚██╗ ██╔╝██╔══██║  ╚██╔╝  ", 'OKBLUE'))
            print(self._colorize(f"  ███████║   ██║   ███████╗╚██████╔╝██║  ██║ ╚████╔╝ ██║  ██║   ██║   ", 'OKBLUE'))
            print(self._colorize(f"  ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚═╝   ╚═╝   ", 'OKBLUE'))
            print(self._colorize(f"\n  {title}", 'BOLD'))
            print(self._colorize(f"  {subtitle}", 'OKCYAN'))
            print(self._colorize(line + "\n", 'OKCYAN'))
        else:
            print(f"\n{line}")
            print(f"  {title}")
            print(f"  {subtitle}")
            print(line + "\n")
    
    def _colorize(self, text: str, color: str) -> str:
        """Add color to text if colors are enabled"""
        if self.use_colors and color in self.COLORS:
            return f"{self.COLORS[color]}{text}{self.COLORS['ENDC']}"
        return text
    
    def print_header(self, text: str):
        """Print header text"""
        print(self._colorize(f"\n{'='*60}", 'OKCYAN'))
        print(self._colorize(f"  {text}", 'BOLD'))
        print(self._colorize(f"{'='*60}\n", 'OKCYAN'))
    
    def print_success(self, text: str):
        """Print success message"""
        print(self._colorize(f"✓ {text}", 'OKGREEN'))
    
    def print_error(self, text: str):
        """Print error message"""
        print(self._colorize(f"✗ {text}", 'FAIL'), file=sys.stderr)
    
    def print_warning(self, text: str):
        """Print warning message"""
        print(self._colorize(f"⚠ {text}", 'WARNING'))
    
    def print_info(self, text: str):
        """Print info message"""
        print(self._colorize(f"ℹ {text}", 'OKBLUE'))
    
    def get_password(self, password: Optional[str] = None) -> str:
        """Get password from user"""
        if password:
            return password
        
        try:
            pwd = getpass.getpass("Enter password: ")
            if not pwd:
                raise ValueError("Password cannot be empty")
            return pwd
        except KeyboardInterrupt:
            print("\n")
            sys.exit(1)
    
    def format_size(self, size: int) -> str:
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"
    
    def print_metadata(self, metadata: Dict):
        """Print metadata information"""
        print(self._colorize("\n📋 Image Metadata", 'BOLD'))
        print(self._colorize("-" * 40, 'OKCYAN'))
        
        if metadata.get('is_archive', False):
            print(f"Type:          Archive (Multiple Files)")
            print(f"File Count:    {metadata['file_count']}")
            print(f"Total Size:    {self.format_size(metadata['total_size'])}")
            print(f"Encrypted:     {'Yes' if metadata['encrypted'] else 'No'}")
            print(f"Compressed:    {'Yes' if metadata['compressed'] else 'No'}")
            print(f"Format Version: {metadata['version']}")
            print(f"Archive Hash:  {metadata['file_hash'].hex()[:16]}...")
        else:
            print(f"Type:          Single File")
            print(f"File Name:     {metadata['file_name']}")
            print(f"File Size:     {self.format_size(metadata['file_size'])}")
            print(f"Encrypted:     {'Yes' if metadata['encrypted'] else 'No'}")
            print(f"Compressed:    {'Yes' if metadata['compressed'] else 'No'}")
            print(f"Format Version: {metadata['version']}")
            print(f"File Hash:     {metadata['file_hash'].hex()[:16]}...")

