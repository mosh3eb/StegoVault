# Installation Guide

## System Requirements

- Python 3.7 or higher
- pip (Python package manager)
- 200MB disk space
- macOS, Linux, or Windows

## Quick Install

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/StegoVault.git
cd StegoVault
```

### 2. Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Tests

```bash
bash run_tests.sh
```

## Installation Verification

```bash
python3 src/stegovault/cli_main.py --help
```

You should see the help menu with available commands.

## Uninstall

```bash
deactivate  # Exit virtual environment
cd ..
rm -rf StegoVault  # Remove directory
```

## Troubleshooting

### Python not found
Ensure Python 3.7+ is installed:
```bash
python3 --version
```

### Module import errors
Reinstall dependencies:
```bash
pip install --upgrade -r requirements.txt
```

### Permission errors on Linux/Mac
Run tests with proper permissions or create a virtual environment.

