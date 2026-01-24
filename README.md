# 🔐 StegoVault

> **Advanced Steganography & Encryption Toolkit**
> 
> Hide secrets inside images with military-grade encryption and anti-detection features.

---

## ✨ Features

🔒 **Military-Grade Security**
- AES-256 encryption for embedded data
- End-to-end encrypted file transfers
- Secure temporary file handling

🖼️ **Multiple Embedding Modes**
- Pixel-level LSB (Least Significant Bit) embedding
- Frequency domain techniques
- Adaptive capacity detection
- Automatic format selection (PNG, BMP, TIFF)

📦 **Multi-File Support**
- Embed multiple files as compressed archives
- Preserve directory structures
- Intelligent file packing

🔍 **Advanced Detection & Analysis**
- Steganalysis with RS analysis
- Chi-square histogram testing
- Risk scoring (0-100 scale)
- Detailed statistical analysis

🛡️ **Anti-Detection Features**
- Histogram preservation
- Histogram matching
- Robustness enhancement
- Adaptive embedding patterns

🌐 **Multiple Interfaces**
- **CLI** - Command-line interface with full feature set
- **GUI** - PyQt5-based graphical interface
- **Web** - Flask-powered browser interface

⚡ **Performance**
- Efficient data compression (zlib)
- Progress tracking
- Batch operations support
- Memory-efficient processing

---

## 🚀 Quick Start

### Installation

**Option 1: From PyPI (Recommended)**
```bash
pip install stegovault
```

**Option 2: From Source**
```bash
# Clone repository
git clone https://github.com/mosh3eb/StegoVault.git
cd StegoVault

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Embed a secret file
python3 bin/stegovault embed secret.txt carrier.png --password "strong_password" --compression

# Extract the hidden file
python3 bin/stegovault extract carrier.png --password "strong_password" --output recovered.txt

# Analyze image for steganography
python3 bin/stegovault detect carrier.png --verbose

# Get image information
python3 bin/stegovault info carrier.png

# Check embedding capacity
python3 bin/stegovault capacity carrier.png
```

### Advanced Usage

```bash
# Archive multiple files
python3 bin/stegovault embed-archive doc1.pdf doc2.txt image.jpg archive.png \
  --password "secret" --compression

# Extract archive
python3 bin/stegovault extract-archive archive.png --output ./recovered --password "secret"

# GUI Application
python3 bin/stegovault-gui

# Web Interface (http://localhost:5000)
python3 bin/stegovault-web
```

---

## 📚 Documentation

- **[Installation Guide](docs/INSTALL.md)** - Detailed setup instructions
- **[Usage Guide](docs/USAGE.md)** - Complete command reference and examples
- **[Development Guide](docs/DEVELOPMENT.md)** - Architecture and contributing guidelines
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute to the project

---

## 🏗️ Project Structure

```
StegoVault/
├── bin/                          # Executable entry points
│   ├── stegovault               # CLI interface
│   ├── stegovault-gui           # GUI launcher
│   └── stegovault-web           # Web server
│
├── src/stegovault/              # Main package (16 modules)
│   ├── core.py                  # Core engine
│   ├── crypto.py                # AES-256 encryption
│   ├── steganalysis.py          # Detection algorithms
│   ├── archive.py               # Archive support
│   ├── ui/                      # User interfaces
│   │   ├── gui/                 # PyQt5 GUI
│   │   └── web/                 # Flask web app
│   └── ...
│
├── docs/                        # Documentation (3 guides)
├── examples/                    # Example scripts (3 working examples)
├── tests/                       # Test suite (8 tests)
├── .vscode/                     # VS Code configuration
├── README.md                    # This file
├── requirements.txt             # Dependencies
└── setup.py                     # Package configuration
```

---

## 🔧 System Requirements

- **Python**: 3.7 or higher
- **OS**: macOS, Linux, or Windows
- **Disk Space**: 200MB (including dependencies)
- **RAM**: 512MB minimum (1GB+ recommended)

---

## 📦 Dependencies

Core dependencies (see `requirements.txt` for details):
- **Pillow** - Image processing
- **pycryptodome** - Cryptography
- **Flask** - Web interface
- **PyQt5** - GUI framework (optional)
- **numpy** - Numerical computations

---

## ✅ Testing

```bash
# Run full test suite
bash run_tests.sh

# Run specific tests with pytest
pytest tests/ -v

# Generate coverage report
pytest tests/ --cov=src/stegovault
```

**Test Coverage**: 8 comprehensive tests covering:
- File embedding and extraction
- Archive creation and extraction
- Image capacity calculation
- Steganography detection
- Metadata handling
- Privacy protection

---

## 🔐 Security Features

### Encryption
- **AES-256-CBC** in authenticated mode
- Secure key derivation (PBKDF2)
- Per-file random initialization vectors

### Data Integrity
- SHA-256 checksums for verification
- CRC32 for quick integrity checks
- Metadata authentication

### Robustness
- Redundancy encoding
- Error correction capabilities
- Format-specific optimizations

### Privacy
- No external network calls
- Local processing only
- Secure temporary file handling
- Memory cleanup after operations

---

## 📖 Examples

### Example 1: Basic File Embedding
```bash
# Embed and extract a single file
python3 examples/example1_basic_embedding.py
```

### Example 2: Multi-File Archives
```bash
# Create and extract file archives
python3 examples/example2_archive_embedding.py
```

### Example 3: Detection & Analysis
```bash
# Analyze images for hidden content
python3 examples/example3_detection_analysis.py
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:
- Code style and standards
- Submitting pull requests
- Reporting issues
- Development workflow

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**Important**: This tool is for educational and legitimate purposes only. Users are responsible for complying with all applicable laws and regulations regarding data privacy, cryptography, and steganography in their jurisdiction.

Never use this tool for:
- Illegal activities
- Privacy violations
- Unauthorized surveillance
- Any unlawful purpose

---

## 🙋 Support & Questions

- **Issues**: Report bugs on [GitHub Issues](https://github.com/mosh3eb/StegoVault/issues)
- **Discussions**: Join our [GitHub Discussions](https://github.com/mosh3eb/StegoVault/discussions)
- **Documentation**: Check the [docs](docs/) folder
- **Examples**: Browse working examples in [examples](examples/)

---

## 🎯 Roadmap

- [ ] GPU acceleration for analysis
- [ ] Additional embedding modes (DCT, DWT)
- [ ] Cloud integration
- [ ] Mobile app support
- [ ] Plugin system for custom algorithms
- [ ] Batch processing GUI

---

## 👨‍💻 Author

**StegoVault** is maintained by [mosh3eb](https://github.com/mosh3eb)

- GitHub: [@mosh3eb](https://github.com/mosh3eb)
- PyPI: [stegovault](https://pypi.org/project/stegovault/)

---

## 📚 References & Resources

- [Steganography Fundamentals](https://en.wikipedia.org/wiki/Steganography)
- [Steganalysis Techniques](https://en.wikipedia.org/wiki/Steganalysis)
- [Cryptography Best Practices](https://cheatsheetseries.owasp.org/)
- [Image File Formats](https://en.wikipedia.org/wiki/Image_file_format)

---

**Made with ❤️ for secure data hiding and privacy protection**
