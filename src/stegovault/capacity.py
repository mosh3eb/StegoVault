"""
Intelligent capacity management for StegoVault
Provides real-time capacity calculations and warnings
"""

import os
from typing import Dict, Optional, Tuple
from PIL import Image
import numpy as np


class CapacityManager:
    """Manages capacity calculations and warnings"""
    
    def __init__(self):
        pass

    def format_size(self, size_bytes: int) -> str:
        """
        Human-readable size formatter used by the GUI.
        
        Args:
            size_bytes: Size in bytes.
        Returns:
            Formatted string in B / KB / MB / GB.
        """
        if size_bytes is None:
            return "0 B"
        try:
            size_bytes = float(size_bytes)
        except (TypeError, ValueError):
            return "0 B"

        if size_bytes < 1024:
            return f"{int(size_bytes)} B"
        size_kb = size_bytes / 1024
        if size_kb < 1024:
            return f"{size_kb:.1f} KB"
        size_mb = size_kb / 1024
        if size_mb < 1024:
            return f"{size_mb:.2f} MB"
        size_gb = size_mb / 1024
        return f"{size_gb:.2f} GB"
    
    def calculate_capacity(self, cover_image: Optional[str] = None,
                          image_size: Optional[Tuple[int, int]] = None,
                          mode: str = 'lsb',
                          quality: int = 95) -> Dict:
        """
        Calculate maximum capacity for embedding
        
        Args:
            cover_image: Path to cover image (if provided)
            image_size: (width, height) if no cover image
            mode: 'lsb' or 'pixel'
            quality: JPEG quality (1-100)
        
        Returns:
            dict: Capacity information
        """
        if cover_image:
            img = Image.open(cover_image)
            width, height = img.size
        elif image_size:
            width, height = image_size
        else:
            return {
                'max_bytes': 0,
                'max_kb': 0,
                'max_mb': 0,
                'available_bits': 0,
                'recommendations': ['No image specified']
            }
        
        # Calculate available bits
        total_pixels = width * height
        
        if mode == 'lsb':
            # LSB mode: 1 bit per channel = 3 bits per pixel
            available_bits = total_pixels * 3
        else:  # pixel mode
            # Pixel mode: 3 bytes per pixel (RGB)
            available_bits = total_pixels * 3 * 8
        
        # Account for metadata overhead
        # Signature(4) + version(1) + sizes(8) + filename(256) + hash(32) + flags(2) + salt/IV(32 if encrypted)
        base_metadata_bits = (4 + 1 + 8 + 256 + 32 + 2) * 8  # ~2500 bits
        encryption_overhead_bits = 32 * 8  # 256 bits
        
        # Available for actual data
        available_data_bits = available_bits - base_metadata_bits - encryption_overhead_bits
        
        # Convert to bytes
        max_bytes = available_data_bits // 8
        
        # Account for compression (if enabled, can fit more)
        compression_factor = 0.7  # Assume 30% compression on average
        max_bytes_compressed = int(max_bytes / compression_factor)
        
        return {
            'max_bytes': max_bytes,
            'max_bytes_compressed': max_bytes_compressed,
            'max_kb': max_bytes / 1024,
            'max_mb': max_bytes / (1024 * 1024),
            'max_kb_compressed': max_bytes_compressed / 1024,
            'max_mb_compressed': max_bytes_compressed / (1024 * 1024),
            'available_bits': available_bits,
            'image_size': (width, height),
            'total_pixels': total_pixels,
            'mode': mode,
            'quality': quality,
            'recommendations': self._generate_recommendations(max_bytes, max_bytes_compressed, mode, quality)
        }
    
    def check_file_fits(self, file_path: str, cover_image: Optional[str] = None,
                       image_size: Optional[Tuple[int, int]] = None,
                       mode: str = 'lsb',
                       compress: bool = False,
                       password: Optional[str] = None) -> Dict:
        """
        Check if a file will fit in the image
        
        Returns:
            dict: Fit analysis with warnings and recommendations
        """
        file_size = os.path.getsize(file_path)
        capacity = self.calculate_capacity(cover_image, image_size, mode)
        
        max_bytes = capacity['max_bytes_compressed'] if compress else capacity['max_bytes']
        
        fits = file_size <= max_bytes
        utilization = (file_size / max_bytes * 100) if max_bytes > 0 else 100
        
        warnings = []
        recommendations = []
        
        if not fits:
            warnings.append(f"File ({file_size:,} bytes) is too large for image capacity ({max_bytes:,} bytes)")
            recommendations.append("Enable compression to increase capacity")
            recommendations.append("Use a larger cover image")
            recommendations.append("Split file into multiple images")
        elif utilization > 90:
            warnings.append(f"File uses {utilization:.1f}% of capacity - very tight fit")
            recommendations.append("Consider enabling compression for safety margin")
        elif utilization > 70:
            warnings.append(f"File uses {utilization:.1f}% of capacity")
            recommendations.append("Consider enabling compression for better quality")
        
        if password and not compress:
            recommendations.append("Consider enabling compression when using encryption")
        
        if mode == 'pixel' and cover_image:
            recommendations.append("Consider using LSB mode for better quality preservation")
        
        return {
            'fits': fits,
            'file_size': file_size,
            'capacity': max_bytes,
            'utilization_percent': utilization,
            'warnings': warnings,
            'recommendations': recommendations,
            'needs_resize': not fits and cover_image is not None
        }
    
    def estimate_required_size(self, file_size: int, mode: str = 'lsb',
                               compress: bool = False) -> Tuple[int, int]:
        """
        Estimate required image size for a file
        
        Returns:
            tuple: (width, height) minimum size needed
        """
        # Account for metadata overhead
        base_metadata_bytes = 300  # Approximate
        encryption_overhead = 50 if compress else 0
        
        if compress:
            # Assume 30% compression
            compressed_size = int(file_size * 0.7)
        else:
            compressed_size = file_size
        
        total_bytes_needed = compressed_size + base_metadata_bytes + encryption_overhead
        
        if mode == 'lsb':
            # 3 bits per pixel = 0.375 bytes per pixel
            pixels_needed = int(total_bytes_needed / 0.375)
        else:  # pixel mode
            # 3 bytes per pixel
            pixels_needed = int(total_bytes_needed / 3)
        
        # Calculate square dimensions
        side_length = int(np.ceil(np.sqrt(pixels_needed)))
        
        # Round up to nearest reasonable size
        if side_length < 512:
            side_length = 512
        elif side_length < 1024:
            side_length = ((side_length + 63) // 64) * 64  # Round to multiple of 64
        else:
            side_length = ((side_length + 127) // 128) * 128  # Round to multiple of 128
        
        return (side_length, side_length)
    
    def _generate_recommendations(self, max_bytes: int, max_bytes_compressed: int,
                                 mode: str, quality: int) -> list:
        """Generate capacity recommendations"""
        recommendations = []
        
        if max_bytes < 1024:
            recommendations.append("Very small capacity - consider using a larger image")
        elif max_bytes < 10240:
            recommendations.append("Small capacity - suitable for text files or small documents")
        elif max_bytes < 102400:
            recommendations.append("Medium capacity - suitable for documents and small images")
        else:
            recommendations.append("Large capacity - suitable for most files")
        
        if mode == 'lsb':
            recommendations.append("LSB mode preserves image quality well")
        else:
            recommendations.append("Pixel mode provides maximum capacity")
        
        if quality < 85:
            recommendations.append("Low quality setting may reduce capacity after recompression")
        
        return recommendations
