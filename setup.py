"""
Setup script for StegoVault
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README if it exists
readme_file = Path(__file__).parent / "README.md"
long_description = ""
if readme_file.exists():
    with open(readme_file, 'r', encoding='utf-8') as f:
        long_description = f.read()

setup(
    name="stegovault",
    version="1.0.0",
    description="Advanced Steganography Tool - Hide files inside images with encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="StegoVault Team",
    url="https://github.com/stegovault/stegovault",
    packages=find_packages(),
    install_requires=[
        "Pillow>=10.0.0",
        "numpy>=1.24.0",
        "cryptography>=41.0.0",
        "tqdm>=4.65.0",
        "PyYAML>=6.0",
        "colorama>=0.4.6",
    ],
    extras_require={
        "gui": ["PyQt6>=6.5.0"],
        "web": ["Flask>=2.3.0", "Werkzeug>=2.3.0"],
        "all": ["PyQt6>=6.5.0", "Flask>=2.3.0", "Werkzeug>=2.3.0"],
    },
    entry_points={
        "console_scripts": [
            "stegovault=main:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)

