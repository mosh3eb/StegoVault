"""
Multi-file archive support for StegoVault
Supports embedding multiple files and folders into a single stego image
"""

import os
import struct
import zlib
import json
import hashlib
from typing import List, Dict, Optional, Tuple
from pathlib import Path


class ArchiveManager:
    """Manages multi-file archives for steganography"""
    
    ARCHIVE_SIGNATURE = b"SVA1"  # StegoVault Archive v1
    
    def __init__(self):
        pass
    
    def create_archive(self, file_paths: List[str], base_path: Optional[str] = None) -> bytes:
        """
        Create an archive from multiple files/folders
        
        Args:
            file_paths: List of file or directory paths to include
            base_path: Base path for relative paths (if None, uses common parent)
        
        Returns:
            bytes: Archive data
        """
        files_data = []
        total_size = 0
        
        # Determine base path
        if base_path is None:
            # Find common parent directory
            abs_paths = [os.path.abspath(p) for p in file_paths]
            if len(abs_paths) == 1:
                base_path = os.path.dirname(abs_paths[0]) or '.'
            else:
                # Find common prefix
                base_path = os.path.commonpath(abs_paths)
        
        base_path = os.path.abspath(base_path)
        
        # Collect all files
        for path in file_paths:
            abs_path = os.path.abspath(path)
            if os.path.isfile(abs_path):
                # Single file
                rel_path = os.path.relpath(abs_path, base_path)
                with open(abs_path, 'rb') as f:
                    file_data = f.read()
                files_data.append({
                    'path': rel_path.replace('\\', '/'),  # Normalize to forward slashes
                    'data': file_data,
                    'size': len(file_data),
                    'is_dir': False
                })
                total_size += len(file_data)
            elif os.path.isdir(abs_path):
                # Directory - recursively add all files
                for root, dirs, filenames in os.walk(abs_path):
                    for filename in filenames:
                        file_path = os.path.join(root, filename)
                        rel_path = os.path.relpath(file_path, base_path)
                        with open(file_path, 'rb') as f:
                            file_data = f.read()
                        files_data.append({
                            'path': rel_path.replace('\\', '/'),
                            'data': file_data,
                            'size': len(file_data),
                            'is_dir': False
                        })
                        total_size += len(file_data)
        
        # Create archive structure
        # Format: [signature(4)] [file_count(4)] [manifest_size(4)] [manifest] [file1_data] [file2_data] ...
        
        # Build manifest (JSON with file info)
        manifest = {
            'version': 1,
            'base_path': base_path.replace('\\', '/'),
            'file_count': len(files_data),
            'total_size': total_size,
            'files': []
        }
        
        for file_info in files_data:
            manifest['files'].append({
                'path': file_info['path'],
                'size': file_info['size'],
                'hash': hashlib.sha256(file_info['data']).hexdigest()
            })
        
        manifest_json = json.dumps(manifest, separators=(',', ':')).encode('utf-8')
        manifest_size = len(manifest_json)
        
        # Build archive
        archive = bytearray()
        archive.extend(self.ARCHIVE_SIGNATURE)
        archive.extend(struct.pack('I', len(files_data)))  # file_count
        archive.extend(struct.pack('I', manifest_size))   # manifest_size
        archive.extend(manifest_json)                      # manifest
        
        # Add file data with size prefix
        for file_info in files_data:
            archive.extend(struct.pack('I', file_info['size']))  # file size
            archive.extend(file_info['data'])                     # file data
        
        return bytes(archive)
    
    def extract_archive(self, archive_data: bytes, output_dir: str = '.') -> Dict:
        """
        Extract archive to directory
        
        Args:
            archive_data: Archive data bytes
            output_dir: Directory to extract to
        
        Returns:
            dict: Archive metadata and extracted file paths
        """
        if len(archive_data) < 12:
            raise ValueError("Invalid archive: too small")
        
        # Check signature
        if archive_data[:4] != self.ARCHIVE_SIGNATURE:
            raise ValueError("Invalid archive signature")
        
        # Parse header
        file_count = struct.unpack('I', archive_data[4:8])[0]
        manifest_size = struct.unpack('I', archive_data[8:12])[0]
        
        if len(archive_data) < 12 + manifest_size:
            raise ValueError("Invalid archive: incomplete manifest")
        
        # Parse manifest
        manifest_json = archive_data[12:12+manifest_size].decode('utf-8')
        manifest = json.loads(manifest_json)
        
        # Extract files
        offset = 12 + manifest_size
        extracted_files = []
        
        for i, file_info in enumerate(manifest['files']):
            if offset + 4 > len(archive_data):
                raise ValueError(f"Invalid archive: incomplete file {i}")
            
            file_size = struct.unpack('I', archive_data[offset:offset+4])[0]
            offset += 4
            
            if offset + file_size > len(archive_data):
                raise ValueError(f"Invalid archive: incomplete file data for {file_info['path']}")
            
            file_data = archive_data[offset:offset+file_size]
            offset += file_size
            
            # Verify hash
            computed_hash = hashlib.sha256(file_data).hexdigest()
            if computed_hash != file_info['hash']:
                raise ValueError(f"File integrity check failed for {file_info['path']}")
            
            # Create output path
            output_path = os.path.join(output_dir, file_info['path'])
            output_path = os.path.normpath(output_path)
            
            # Create directory if needed
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Write file
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            extracted_files.append(output_path)
        
        return {
            'manifest': manifest,
            'extracted_files': extracted_files,
            'file_count': len(extracted_files),
            'total_size': manifest['total_size']
        }
    
    def get_archive_info(self, archive_data: bytes) -> Optional[Dict]:
        """Get archive metadata without extracting"""
        try:
            if len(archive_data) < 12:
                return None
            
            if archive_data[:4] != self.ARCHIVE_SIGNATURE:
                return None
            
            file_count = struct.unpack('I', archive_data[4:8])[0]
            manifest_size = struct.unpack('I', archive_data[8:12])[0]
            
            if len(archive_data) < 12 + manifest_size:
                return None
            
            manifest_json = archive_data[12:12+manifest_size].decode('utf-8')
            manifest = json.loads(manifest_json)
            
            return manifest
        except Exception:
            return None
