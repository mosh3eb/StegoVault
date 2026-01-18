#!/usr/bin/env python3
"""
StegoVault - Advanced Steganography Tool
A powerful, cross-platform tool for hiding files inside images with encryption and advanced features.
"""

import argparse
import sys
import os
from pathlib import Path
from stegovault.core import StegoEngine
from stegovault.crypto import CryptoManager
from stegovault.cli import CLIInterface
from stegovault.config import get_config


def main():
    parser = argparse.ArgumentParser(
        description='StegoVault - Advanced Steganography Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create image from file (no cover needed)
  %(prog)s embed secret.txt
  
  # Create image with custom output name
  %(prog)s embed secret.txt output.png
  
  # Embed file into existing cover image
  %(prog)s embed secret.txt output.png --cover photo.jpg
  
  # Embed with password encryption
  %(prog)s embed secret.txt output.png --password "mypass"
  
  # Extract file from image
  %(prog)s extract output.png
  
  # Extract with password
  %(prog)s extract output.png --password "mypass"
  
  # View metadata without extracting
  %(prog)s info output.png
  
  # Use LSB mode for more natural-looking images
  %(prog)s embed secret.txt output.png --mode lsb --password "mypass"
  
  # Batch embed multiple files
  %(prog)s embed-batch file1.txt file2.txt cover.png output.png --password "mypass"
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Embed command
    embed_parser = subparsers.add_parser('embed', help='Embed a file into an image')
    embed_parser.add_argument('input_file', help='File to embed')
    embed_parser.add_argument('output_image', nargs='?', help='Output stego image (optional, auto-generated if not provided)')
    embed_parser.add_argument('--cover', '-c', dest='cover_image', help='Cover image (PNG/JPG). If not provided, creates new image from scratch')
    embed_parser.add_argument('--password', '-p', help='Password for encryption (optional)')
    embed_parser.add_argument('--mode', '-m', choices=['pixel', 'lsb'], default='pixel',
                             help='Steganography mode: pixel (fast) or lsb (stealthy)')
    embed_parser.add_argument('--compression', action='store_true',
                             help='Compress data before embedding')
    embed_parser.add_argument('--quality', '-q', type=int, default=95, choices=range(1, 101),
                             help='Output image quality (1-100, default: 95)')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract file from stego image')
    extract_parser.add_argument('stego_image', help='Stego image containing hidden file')
    extract_parser.add_argument('--output', '-o', help='Output file path (default: original filename)')
    extract_parser.add_argument('--password', '-p', help='Password for decryption (if encrypted)')
    extract_parser.add_argument('--verify', '-v', action='store_true',
                               help='Verify file integrity after extraction')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='View metadata without extracting')
    info_parser.add_argument('stego_image', help='Stego image to inspect')
    info_parser.add_argument('--password', '-p', help='Password (if encrypted)')
    
    # Batch embed command
    batch_parser = subparsers.add_parser('embed-batch', help='Embed multiple files into one image')
    batch_parser.add_argument('input_files', nargs='+', help='Files to embed')
    batch_parser.add_argument('cover_image', help='Cover image')
    batch_parser.add_argument('output_image', help='Output stego image')
    batch_parser.add_argument('--password', '-p', help='Password for encryption')
    batch_parser.add_argument('--mode', '-m', choices=['pixel', 'lsb'], default='pixel')
    batch_parser.add_argument('--compression', '-c', action='store_true')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    cli = CLIInterface()
    engine = StegoEngine()
    crypto = CryptoManager()
    config = get_config()
    
    try:
        if args.command == 'embed':
            cli.print_header("Embedding file into image...")
            password = cli.get_password(args.password) if args.password else None
            
            if password:
                cli.print_info("Using AES-256 encryption")
            
            # Determine output image name
            output_img = args.output_image
            if output_img is None:
                base_name = os.path.splitext(os.path.basename(args.input_file))[0]
                output_img = f"{base_name}_stego.png"
                cli.print_info(f"Output image: {output_img} (auto-generated)")
            
            if args.cover_image:
                cli.print_info(f"Using cover image: {args.cover_image}")
            else:
                cli.print_info("Creating new image from scratch")
            
            # Get defaults from config
            mode = args.mode or config.get('defaults', {}).get('mode', 'pixel')
            quality = args.quality or config.get('defaults', {}).get('quality', 95)
            compress = args.compression or config.get('defaults', {}).get('compression', False)
            show_progress = config.get('defaults', {}).get('show_progress', True)
            
            success = engine.embed_file(
                input_file=args.input_file,
                cover_image=args.cover_image,
                output_image=output_img,
                password=password,
                mode=mode,
                compress=compress,
                quality=quality,
                show_progress=show_progress
            )
            
            if success:
                cli.print_success(f"File embedded successfully: {output_img}")
                file_size = os.path.getsize(output_img)
                cli.print_info(f"Output image size: {cli.format_size(file_size)}")
            else:
                cli.print_error("Failed to embed file")
                sys.exit(1)
        
        elif args.command == 'extract':
            cli.print_header("Extracting file from image...")
            password = cli.get_password(args.password) if args.password else None
            
            output_path = engine.extract_file(
                stego_image=args.stego_image,
                output_path=args.output,
                password=password,
                verify=args.verify
            )
            
            if output_path:
                cli.print_success(f"File extracted successfully: {output_path}")
                file_size = os.path.getsize(output_path)
                cli.print_info(f"Extracted file size: {cli.format_size(file_size)}")
            else:
                cli.print_error("Failed to extract file")
                sys.exit(1)
        
        elif args.command == 'info':
            cli.print_header("Reading image metadata...")
            password = cli.get_password(args.password) if args.password else None
            
            metadata = engine.get_metadata(args.stego_image, password)
            if metadata:
                cli.print_metadata(metadata)
            else:
                cli.print_error("Could not read metadata. File may not be a stego image.")
                sys.exit(1)
        
        elif args.command == 'embed-batch':
            cli.print_header("Embedding multiple files...")
            password = cli.get_password(args.password) if args.password else None
            
            # Batch embedding would require additional implementation
            cli.print_error("Batch embedding not yet implemented")
            sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n")
        cli.print_warning("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        cli.print_error(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()

