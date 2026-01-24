#!/usr/bin/env python3
"""
Example 2: Archive Multiple Files

This example shows how to embed multiple files as an archive
into a single image.
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
    engine = StegoEngine()
    
    # Create test files
    files_to_archive = []
    for i in range(3):
        filename = f"document_{i}.txt"
        with open(filename, 'w') as f:
            f.write(f"This is document {i}\nContent example for archiving")
        files_to_archive.append(filename)
    
    print(f"Created {len(files_to_archive)} files for archiving")
    
    # Embed as archive
    print("\nEmbedding archive into image...")
    output_image = "example_archive.png"
    password = "archive_password"
    
    success = engine.embed_archive(
        file_paths=files_to_archive,
        output_image=output_image,
        password=password
    )
    
    if success:
        print(f"✓ Archive embedded successfully to: {output_image}")
        
        # Extract archive
        print("\nExtracting archive from image...")
        extract_dir = "example_extracted"
        
        result = engine.extract_archive(
            stego_image=output_image,
            output_dir=extract_dir,
            password=password
        )
        
        if result:
            print(f"✓ Archive extracted successfully!")
            print(f"  Extracted {result['file_count']} files")
            print(f"  Total size: {result['total_size']} bytes")
        else:
            print("✗ Failed to extract archive")
    else:
        print("✗ Failed to embed archive")

if __name__ == '__main__':
    main()
