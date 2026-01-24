# Contributing to StegoVault

We appreciate your interest in contributing to StegoVault! This document provides guidelines for contributions.

## Code of Conduct

- Be respectful and inclusive
- Follow professional standards
- Respect intellectual property
- Use this tool responsibly and legally

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/StegoVault.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Set up development environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Development Workflow

### 1. Make Changes

- Keep changes focused on a single feature or fix
- Write clear, documented code
- Follow PEP 8 style guide

### 2. Test Your Changes

```bash
bash run_tests.sh
```

All tests must pass before submitting.

### 3. Code Quality

```bash
# Format code
black src/

# Check linting
flake8 src/

# Type checking
mypy src/ --ignore-missing-imports
```

### 4. Commit Messages

Use clear, descriptive commit messages:

```
feat: Add new embedding mode support
fix: Resolve memory leak in archive extraction
docs: Update installation guide
test: Add tests for capacity calculation
```

### 5. Submit Pull Request

- Describe your changes clearly
- Reference any related issues
- Ensure all tests pass
- Request review from maintainers

## Code Style Guide

### Python Style

```python
# Use type hints
def embed_file(self, file_path: str, password: Optional[str] = None) -> bool:
    """
    Embed a file into an image.
    
    Args:
        file_path: Path to the file to embed
        password: Optional encryption password
    
    Returns:
        bool: Success status
    """
    pass
```

### Documentation

- Include docstrings for all functions and classes
- Use Google-style docstrings
- Add examples in docstrings where helpful

```python
def extract_file(self, image_path: str) -> Optional[bytes]:
    """
    Extract embedded file from image.
    
    Example:
        >>> engine = StegoEngine()
        >>> data = engine.extract_file('stego.png')
        >>> len(data)
        1024
    
    Args:
        image_path: Path to stego image
    
    Returns:
        Extracted file data or None if extraction failed
    """
```

## Reporting Issues

### Bug Reports

Include:
- Python version and OS
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

### Feature Requests

Include:
- Clear description of the feature
- Use cases
- Potential implementation approach

## Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Update CHANGELOG.md
4. Ensure CI passes
5. Request review from maintainers
6. Address feedback
7. Merge when approved

## Testing

### Write Tests

Tests should be in `tests/` directory:

```python
import pytest
from stegovault.core import StegoEngine

class TestEmbedding:
    def test_embed_file_success(self):
        engine = StegoEngine()
        assert engine.embed_file('test.txt', 'output.png')
    
    def test_embed_with_password(self):
        engine = StegoEngine()
        assert engine.embed_file('test.txt', 'output.png', password='secret')
```

### Run Tests

```bash
# Run all tests
bash run_tests.sh

# Run specific test
pytest tests/test_embedding.py -v

# Run with coverage
pytest tests/ --cov=src/stegovault
```

## Documentation Updates

- Update README.md for significant changes
- Update docs/USAGE.md for new commands
- Update docs/DEVELOPMENT.md for architectural changes
- Add examples if introducing new features

## Performance Considerations

- Profile code before/after changes
- Avoid unnecessary copying of data
- Consider memory usage for large files
- Use efficient algorithms

## Security Considerations

- Never commit passwords or keys
- Use secure temporary file handling
- Validate all input
- Follow encryption best practices
- Document security implications

## Licensing

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Open a discussion on GitHub
- Email the maintainers
- Check existing documentation

Thank you for contributing to StegoVault! 🙏

