#!/usr/bin/env python3
"""
Example 3: Detection and Analysis

This example demonstrates steganography detection and image analysis.
"""

import sys
from pathlib import Path

# Add src to path for runtime imports
project_root = Path(__file__).parent.parent
src_path = project_root / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from stegovault.core import StegoEngine
from stegovault.steganalysis import SteganalysisProtection

try:
    from PIL import Image  # type: ignore
except ImportError:
    Image = None  # type: ignore

def main():
    engine = StegoEngine()
    
    # Create a test image with embedded data
    test_file = "secret_analysis.txt"
    with open(test_file, 'w') as f:
        f.write("Hidden data for analysis")
    
    print("Creating stego image...")
    stego_image = "example_analysis.png"
    password = "analysis_password"
    
    engine.embed_file(
        input_file=test_file,
        output_image=stego_image,
        password=password
    )
    
    # Get image information
    print("\n" + "="*50)
    print("Image Information")
    print("="*50)
    
    metadata = engine.get_metadata(stego_image, password=password)
    if metadata:
        print(f"File Name: {metadata.get('filename')}")
        print(f"File Size: {metadata.get('file_size')} bytes")
        print(f"Encrypted: {metadata.get('encrypted')}")
        print(f"Compressed: {metadata.get('compressed')}")
        checksum = metadata.get('checksum')
        if checksum:
            print(f"Checksum: {checksum[:16]}...")
    
    # Detect steganography
    print("\n" + "="*50)
    print("Steganography Detection")
    print("="*50)
    
    detection = engine.detect_steganography(stego_image)
    print(f"Risk Score: {detection.get('risk_score')}/100")
    print(f"Risk Level: {detection.get('risk_level')}")
    print(f"Detected: {'Yes' if detection.get('detected') else 'No'}")
    
    if 'lsb_analysis' in detection:
        print(f"\nLSB Analysis:")
        print(f"  Transition Rate: {detection['lsb_analysis'].get('transition_rate', 0):.3f}")
    
    # Calculate capacity
    print("\n" + "="*50)
    print("Image Capacity")
    print("="*50)
    
    if Image is not None:
        img = Image.open(stego_image)
        print(f"Image Size: {img.size}")
        print(f"Image Format: {img.format}")
        
        # Estimate capacity (rough calculation)
        width, height = img.size
        max_bytes = (width * height * 3) // 8  # LSB embedding
        print(f"Maximum Capacity: {max_bytes} bytes (~{max_bytes/1024:.1f} KB)")
    else:
        print("PIL not installed - skipping image analysis")

if __name__ == '__main__':
    main()
