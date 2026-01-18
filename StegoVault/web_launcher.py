#!/usr/bin/env python3
"""
Launch the StegoVault web application
"""

import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from web.app import app

if __name__ == '__main__':
    print("Starting StegoVault Web Interface...")
    print("Open http://localhost:5000 in your browser")
    app.run(debug=True, host='0.0.0.0', port=5000)

