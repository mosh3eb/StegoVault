"""
Netlify serverless function for StegoVault Flask app.
Wraps the Flask application to run on Netlify Functions (AWS Lambda).
"""

import os
import sys
from pathlib import Path

# Add src directory to path for imports
src_path = str(Path(__file__).parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Import the Flask app from the web module
try:
    from stegovault.ui.web.app import app
except ImportError:
    from StegoVault.ui.web.app import app

# Export the handler for Netlify
handler = app
