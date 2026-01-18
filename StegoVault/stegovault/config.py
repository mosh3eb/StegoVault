"""
Configuration management
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict


def get_config() -> Dict[str, Any]:
    """Load configuration from file or return defaults"""
    config_path = Path.home() / '.stegovault' / 'config.yaml'
    
    defaults = {
        'defaults': {
            'mode': 'pixel',
            'quality': 95,
            'compression': False,
            'show_progress': True,
        }
    }
    
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f) or {}
                # Merge with defaults
                defaults.update(user_config)
        except Exception:
            pass
    
    return defaults

