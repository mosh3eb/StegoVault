# Development Guide

## Project Architecture

### Core Modules

- **core.py** - Main steganography engine (embedding/extraction)
- **crypto.py** - AES-256 encryption and key management
- **steganalysis.py** - Detection algorithms (RS analysis, histogram)
- **archive.py** - Multi-file archive creation and extraction
- **cli.py** - Command-line interface utilities
- **config.py** - Configuration management
- **capacity.py** - Embedding capacity calculations
- **metadata.py** - Metadata handling
- **robustness.py** - Robustness features
- **errors.py** - Custom exceptions

### UI Modules

- **ui/gui/** - PyQt5-based GUI application
- **ui/web/** - Flask web interface with JavaScript frontend

## Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/yourusername/StegoVault.git
cd StegoVault

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt
pip install pytest black flake8

# Run tests
bash run_tests.sh
```

## Code Style

We follow PEP 8 with these conventions:

```bash
# Format code
black src/

# Lint code
flake8 src/
```

## Adding New Features

### 1. Create Feature Branch

```bash
git checkout -b feature/my-feature
```

### 2. Implement Feature

Follow the existing code structure:
- Add methods to appropriate modules
- Include docstrings
- Add error handling

### 3. Write Tests

Add tests to `tests/` directory:

```python
# tests/test_my_feature.py
import pytest
from stegovault.module import function

def test_feature():
    result = function()
    assert result is not None
```

### 4. Run Tests

```bash
bash run_tests.sh
pytest tests/
```

### 5. Submit Pull Request

## Key Classes

### StegoEngine

Main class for embedding and extraction:

```python
from stegovault.core import StegoEngine

engine = StegoEngine()
success = engine.embed_file(
    input_file='secret.txt',
    output_image='stego.png',
    password='mypass'
)
```

### CryptoManager

Handles encryption/decryption:

```python
from stegovault.crypto import CryptoManager

crypto = CryptoManager()
encrypted = crypto.encrypt(data, password)
decrypted = crypto.decrypt(encrypted, password)
```

### SteganalysisProtection

Detection and analysis:

```python
from stegovault.steganalysis import SteganalysisProtection

analyzer = SteganalysisProtection()
result = analyzer.detect_steganography(image)
```

## Testing

### Run All Tests

```bash
bash run_tests.sh
```

### Run Specific Tests

```bash
python3 -m pytest tests/test_specific.py -v
```

### Test Coverage

```bash
pip install coverage
coverage run -m pytest tests/
coverage report
```

## Debugging

Enable debug output:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Performance Optimization

Profile code:

```bash
python3 -m cProfile -s cumtime src/stegovault/cli_main.py embed test.txt output.png
```

## Documentation

Generate API documentation:

```bash
pip install sphinx
sphinx-quickstart docs/
make html -C docs/
```

## Deployment

### Build Package

```bash
python3 setup.py sdist bdist_wheel
```

### Upload to PyPI

```bash
pip install twine
twine upload dist/*
```

## Troubleshooting

### Import Errors

Ensure PYTHONPATH includes src directory:

```bash
export PYTHONPATH="${PWD}/src:${PYTHONPATH}"
```

### Test Failures

Check Python version (3.7+):
```bash
python3 --version
```

Reinstall dependencies:
```bash
pip install --upgrade -r requirements.txt
```

