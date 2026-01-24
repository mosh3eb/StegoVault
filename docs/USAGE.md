# Usage Guide

## Command Line Interface (CLI)

### Basic Commands

#### Embed a File

Embed a file into an image with optional password protection:

```bash
python3 src/stegovault/cli_main.py embed <input_file> [output_image] [options]
```

**Example:**
```bash
python3 src/stegovault/cli_main.py embed secret.txt secret.png --password "mypass123"
```

**Options:**
- `--password TEXT` - Password to encrypt the file
- `--mode {pixel,frequency}` - Embedding mode (default: pixel)
- `--compression` - Enable compression (reduces data size)
- `--quality INT` - JPEG quality (default: 95)

#### Extract a File

Extract an embedded file from an image:

```bash
python3 src/stegovault/cli_main.py extract <stego_image> [options]
```

**Example:**
```bash
python3 src/stegovault/cli_main.py extract secret.png --password "mypass123" --output recovered.txt
```

**Options:**
- `--password TEXT` - Password to decrypt (if encrypted)
- `--output PATH` - Output file path

#### Get Image Information

View metadata of a stego image:

```bash
python3 src/stegovault/cli_main.py info <stego_image> [options]
```

**Example:**
```bash
python3 src/stegovault/cli_main.py info secret.png
```

#### Check Embedding Capacity

Check how much data can be embedded:

```bash
python3 src/stegovault/cli_main.py capacity <image_path>
```

#### Detect Steganography

Analyze an image for potential steganography:

```bash
python3 src/stegovault/cli_main.py detect <image_path> [--verbose]
```

#### Multi-File Archives

Embed multiple files as an archive:

```bash
python3 src/stegovault/cli_main.py embed-archive <file1> <file2> ... <output_image> [options]
```

Extract archive:

```bash
python3 src/stegovault/cli_main.py extract-archive <stego_image> --output <directory> [options]
```

### Advanced Options

#### Robustness
```bash
python3 src/stegovault/cli_main.py embed secret.txt output.png --robustness
```

#### Anti-Steganalysis
```bash
python3 src/stegovault/cli_main.py embed secret.txt output.png --anti-steganalysis
```

## Graphical User Interface (GUI)

Launch the GUI application:

```bash
python3 bin/stegovault-gui
```

## Web Interface

Start the web server:

```bash
python3 bin/stegovault-web
```

Then open your browser to `http://localhost:5000`

## Common Workflows

### Scenario 1: Secure File Transfer

1. Embed sensitive file:
```bash
python3 src/stegovault/cli_main.py embed important.pdf carrier.png --password "strongpass" --compression
```

2. Send carrier.png safely
3. Recipient extracts:
```bash
python3 src/stegovault/cli_main.py extract carrier.png --password "strongpass" --output important.pdf
```

### Scenario 2: Archive Multiple Files

```bash
python3 src/stegovault/cli_main.py embed-archive doc1.pdf doc2.txt image.jpg archive.png --password "secret"
```

Extract:
```bash
python3 src/stegovault/cli_main.py extract-archive archive.png --output ./recovered --password "secret"
```

### Scenario 3: Verify Image Authenticity

```bash
python3 src/stegovault/cli_main.py info image.png
python3 src/stegovault/cli_main.py detect image.png --verbose
```

