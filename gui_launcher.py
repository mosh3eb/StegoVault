#!/usr/bin/env python3
"""
Launch the StegoVault GUI application
"""

import sys
import os
from pathlib import Path

# Add parent directory to path for imports
current_dir = Path(__file__).parent.absolute()
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from gui.main_window import main

if __name__ == '__main__':
    main()

