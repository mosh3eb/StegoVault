#!/usr/bin/env python3
"""
StegoVault - Advanced Steganography Tool
A powerful, cross-platform tool for hiding files inside images with encryption and advanced features.
"""

import argparse
import sys
import os
from pathlib import Path

# Add current directory to path for imports
current_dir = Path(__file__).parent.absolute()
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

try:
    # Preferred (repo/package name)
    from stegovault.core import StegoEngine
    from stegovault.crypto import CryptoManager
    from stegovault.cli import CLIInterface
    from stegovault.config import get_config
except ModuleNotFoundError:
    # Fallback for case-sensitive filesystems where the folder is named `StegoVault/`
    from StegoVault.core import StegoEngine
    from StegoVault.crypto import CryptoManager
    from StegoVault.cli import CLIInterface
    from StegoVault.config import get_config


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
  
  # Embed archive (multiple files/folders)
  %(prog)s embed-archive file1.txt folder1/ output.png --cover photo.jpg --password "mypass"
  
  # Extract archive
  %(prog)s extract-archive output.png --output ./extracted --password "mypass"
  
  # Detect steganography
  %(prog)s detect image.png --verbose
  
  # Check capacity
  %(prog)s capacity cover.jpg --file large.zip --compress
  
  # Privacy analysis
  %(prog)s privacy photo.jpg --strip --output clean.jpg
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
    embed_parser.add_argument('--robustness', '-r', action='store_true',
                             help='Enable social media robustness (error correction + redundancy)')
    embed_parser.add_argument('--anti-steganalysis', '-a', action='store_true',
                             help='Enable anti-steganalysis protection (histogram preservation)')
    embed_parser.add_argument('--strip-metadata', action='store_true',
                             help='Strip EXIF and other metadata from cover image')
    
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
    
    # Archive embed command
    archive_parser = subparsers.add_parser('embed-archive', help='Embed multiple files/folders as archive')
    archive_parser.add_argument('input_paths', nargs='+', help='Files or directories to embed')
    archive_parser.add_argument('output_image', help='Output stego image')
    archive_parser.add_argument('--cover', '-c', dest='cover_image', help='Cover image (optional)')
    archive_parser.add_argument('--password', '-p', help='Password for encryption')
    archive_parser.add_argument('--mode', '-m', choices=['pixel', 'lsb'], default='lsb',
                               help='Steganography mode')
    archive_parser.add_argument('--compression', action='store_true', default=True,
                               help='Compress archive (default: enabled)')
    archive_parser.add_argument('--robustness', '-r', action='store_true',
                               help='Enable social media robustness')
    archive_parser.add_argument('--anti-steganalysis', '-a', action='store_true',
                               help='Enable anti-steganalysis protection')
    archive_parser.add_argument('--strip-metadata', action='store_true',
                               help='Strip metadata from cover image')
    
    # Archive extract command
    archive_extract_parser = subparsers.add_parser('extract-archive', help='Extract archive from stego image')
    archive_extract_parser.add_argument('stego_image', help='Stego image containing archive')
    archive_extract_parser.add_argument('--output', '-o', default='.', help='Output directory (default: current directory)')
    archive_extract_parser.add_argument('--password', '-p', help='Password for decryption')
    archive_extract_parser.add_argument('--robustness', '-r', action='store_true',
                                       help='Enable robustness recovery')
    
    # Detect command
    detect_parser = subparsers.add_parser('detect', help='Detect steganography in image')
    detect_parser.add_argument('image', help='Image to analyze')
    detect_parser.add_argument('--verbose', '-v', action='store_true',
                              help='Show detailed analysis')
    
    # Capacity command
    capacity_parser = subparsers.add_parser('capacity', help='Check capacity of image')
    capacity_parser.add_argument('image', nargs='?', help='Cover image (optional)')
    capacity_parser.add_argument('--file', '-f', help='Check if specific file fits')
    capacity_parser.add_argument('--mode', '-m', choices=['pixel', 'lsb'], default='lsb',
                                help='Steganography mode')
    capacity_parser.add_argument('--compress', action='store_true',
                                help='Account for compression')
    
    # Privacy command
    privacy_parser = subparsers.add_parser('privacy', help='Analyze image privacy/metadata')
    privacy_parser.add_argument('image', help='Image to analyze')
    privacy_parser.add_argument('--strip', '-s', action='store_true',
                               help='Strip metadata and save cleaned image')
    privacy_parser.add_argument('--output', '-o', help='Output path for cleaned image')
    
    # Batch embed command (deprecated - use embed-archive instead)
    batch_parser = subparsers.add_parser('embed-batch', help='[DEPRECATED] Use embed-archive instead')
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
    cli.print_header("StegoVault 2.0 - Secure Steganography")
    # Initialize engine
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
            
            # Show auto-actions if any
            if hasattr(engine, '_auto_actions') and engine._auto_actions:
                for action in engine._auto_actions:
                    cli.print_info(f"ℹ {action}")
            
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
        
        elif args.command == 'embed-archive':
            cli.print_header("Embedding archive into image...")
            password = cli.get_password(args.password) if args.password else None
            
            if password:
                cli.print_info("Using AES-256 encryption")
            
            cli.print_info(f"Embedding {len(args.input_paths)} file(s)/folder(s)")
            
            success = engine.embed_archive(
                file_paths=args.input_paths,
                cover_image=getattr(args, 'cover_image', None),
                output_image=args.output_image,
                password=password,
                mode=args.mode,
                compress=args.compression
            )
            
            if success:
                cli.print_success(f"Archive embedded successfully: {args.output_image}")
                file_size = os.path.getsize(args.output_image)
                cli.print_info(f"Output image size: {cli.format_size(file_size)}")
                if hasattr(engine, '_auto_actions') and engine._auto_actions:
                    for action in engine._auto_actions:
                        cli.print_info(f"ℹ {action}")
            else:
                cli.print_error("Failed to embed archive")
                sys.exit(1)
        
        elif args.command == 'extract-archive':
            cli.print_header("Extracting archive from image...")
            password = cli.get_password(args.password) if args.password else None
            
            result = engine.extract_archive(
                stego_image=args.stego_image,
                output_dir=args.output,
                password=password
            )
            
            if result:
                cli.print_success(f"Archive extracted successfully to: {args.output}")
                cli.print_info(f"Extracted {result['file_count']} file(s)")
                cli.print_info(f"Total size: {cli.format_size(result['total_size'])}")
                if hasattr(engine, '_auto_actions') and engine._auto_actions:
                    for action in engine._auto_actions:
                        cli.print_info(f"ℹ {action}")
            else:
                cli.print_error("Failed to extract archive")
                sys.exit(1)
        
        elif args.command == 'detect':
            cli.print_header("Analyzing image for steganography...")
            
            detection = engine.detect_steganography(args.image)
            
            if 'error' in detection:
                cli.print_error(detection['error'])
                sys.exit(1)
            
            cli.print_info(f"\n📊 Detection Results:")
            cli.print_info(f"Risk Score: {detection['risk_score']}/100")
            cli.print_info(f"Risk Level: {detection['risk_level']}")
            cli.print_info(f"Detected: {'Yes' if detection['detected'] else 'No'}")
            
            if args.verbose:
                cli.print_info(f"\nLSB Analysis:")
                lsb = detection['lsb_analysis']
                cli.print_info(f"  Transition Rate: {lsb['transition_rate']:.3f}")
                cli.print_info(f"  Suspicious Patterns: {lsb['suspicious_patterns']:.3f}")
                
                cli.print_info(f"\nHistogram Analysis:")
                hist = detection['histogram_analysis']
                cli.print_info(f"  Anomaly Score: {hist['anomaly_score']:.3f}")
                cli.print_info(f"  Anomalies Detected: {hist['anomalies_detected']}")
                
                cli.print_info(f"\nRS Analysis:")
                rs = detection['rs_analysis']
                cli.print_info(f"  Detected: {rs['detected']}")
                cli.print_info(f"  Imbalance: {rs['imbalance']:.3f}")
        
        elif args.command == 'capacity':
            cli.print_header("Capacity Analysis")
            
            if args.image:
                capacity = engine.get_capacity_info(cover_image=args.image, mode=args.mode)
                cli.print_info(f"\nImage: {args.image}")
                cli.print_info(f"Size: {capacity['image_size'][0]}x{capacity['image_size'][1]} pixels")
                cli.print_info(f"Mode: {capacity['mode']}")
                cli.print_info(f"\nCapacity:")
                cli.print_info(f"  Maximum: {capacity['max_kb']:.2f} KB ({capacity['max_mb']:.3f} MB)")
                if args.compress:
                    cli.print_info(f"  With Compression: {capacity['max_kb_compressed']:.2f} KB ({capacity['max_mb_compressed']:.3f} MB)")
                
                cli.print_info(f"\nRecommendations:")
                for rec in capacity['recommendations']:
                    cli.print_info(f"  • {rec}")
                
                if args.file:
                    fit_analysis = engine.check_file_fits(
                        args.file, cover_image=args.image, mode=args.mode,
                        compress=args.compress
                    )
                    cli.print_info(f"\nFile Fit Analysis:")
                    cli.print_info(f"  File: {args.file}")
                    cli.print_info(f"  Size: {cli.format_size(fit_analysis['file_size'])}")
                    cli.print_info(f"  Fits: {'Yes' if fit_analysis['fits'] else 'No'}")
                    cli.print_info(f"  Utilization: {fit_analysis['utilization_percent']:.1f}%")
                    
                    if fit_analysis['warnings']:
                        cli.print_warning("\nWarnings:")
                        for warning in fit_analysis['warnings']:
                            cli.print_warning(f"  ⚠ {warning}")
                    
                    if fit_analysis['recommendations']:
                        cli.print_info("\nRecommendations:")
                        for rec in fit_analysis['recommendations']:
                            cli.print_info(f"  • {rec}")
            else:
                cli.print_error("Please specify an image file")
                sys.exit(1)
        
        elif args.command == 'privacy':
            cli.print_header("Privacy Analysis")
            
            report = engine.get_privacy_report(args.image)
            
            cli.print_info(f"\nImage: {args.image}")
            cli.print_info(f"File Size: {cli.format_size(report['metadata']['file_size'])}")
            
            if report['metadata']['has_exif']:
                cli.print_warning("⚠ EXIF data found")
                cli.print_info(f"  EXIF tags: {len(report['metadata']['exif'])}")
            
            if report['metadata']['has_gps']:
                cli.print_warning("⚠ GPS location data found!")
                cli.print_info("  This reveals where the photo was taken")
            
            if report['privacy_risks']:
                cli.print_warning(f"\n⚠ Found {report['risk_count']} privacy risk(s):")
                for risk in report['privacy_risks']:
                    cli.print_warning(f"\n  Risk Level: {risk['risk']}")
                    cli.print_warning(f"  Type: {risk['type']}")
                    cli.print_info(f"  {risk['description']}")
                    cli.print_info(f"  Recommendation: {risk['recommendation']}")
            else:
                cli.print_success("✅ No privacy risks detected")
            
            if args.strip:
                output_path = args.output or args.image.replace('.jpg', '_clean.jpg').replace('.jpeg', '_clean.jpg').replace('.png', '_clean.png')
                cli.print_info(f"\nStripping metadata...")
                clean_image = engine.strip_metadata(args.image, output_path)
                cli.print_success(f"Cleaned image saved to: {clean_image}")
        
        elif args.command == 'embed-batch':
            cli.print_warning("⚠ 'embed-batch' is deprecated. Use 'embed-archive' instead.")
            cli.print_header("Embedding archive (using embed-archive)...")
            password = cli.get_password(args.password) if args.password else None
            
            success = engine.embed_archive(
                file_paths=args.input_files,
                cover_image=args.cover_image,
                output_image=args.output_image,
                password=password,
                mode=args.mode,
                compress=args.compression
            )
            
            if success:
                cli.print_success(f"Archive embedded successfully: {args.output_image}")
            else:
                cli.print_error("Failed to embed archive")
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

