#!/usr/bin/env python3
"""
Example 1: Basic File Embedding

This example demonstrates how to embed a file into an image
and later extract it.
"""

import sys
from pathlib import Path

# Add src to path for runtime imports
project_root = Path(__file__).parent.parent
src_path = project_root / 'src'
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from stegovault.core import StegoEngine

def main():
    # Initialize engine
    engine = StegoEngine()
    
    # Create a test file to embed
    test_file = "example_secret.txt"
    with open(test_file, 'w') as f:
        f.write("This is a secret message!\nIt's hidden inside an image.")
    
    # Embed the file
    print("Embedding file into image...")
    output_image = "example_stego.png"
    password = "my_secret_password"
    
    success = engine.embed_file(
        input_file=test_file,
        output_image=output_image,
        password=password,
        show_progress=True
    )
    
    if success:
        print(f"✓ File embedded successfully to: {output_image}")
        
        # Extract the file back
        print("\nExtracting file from image...")
        extracted_file = "example_recovered.txt"
        
        recovered_path = engine.extract_file(
            stego_image=output_image,
            output_path=extracted_file,
            password=password
        )
        
        if recovered_path:
            print(f"✓ File extracted successfully to: {recovered_path}")
            
            # Verify the content
            with open(extracted_file, 'r') as f:
                content = f.read()
                print(f"\nRecovered content:\n{content}")
        else:
            print("✗ Failed to extract file")
    else:
        print("✗ Failed to embed file")

if __name__ == '__main__':
    main()
