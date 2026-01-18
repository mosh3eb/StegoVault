"""
Core steganography engine for embedding and extracting files
"""

import os
import struct
import zlib
import hashlib
from typing import Optional, Dict
from PIL import Image
import numpy as np
from .crypto import CryptoManager


class StegoEngine:
    """Main steganography engine"""
    
    SIGNATURE = b"SV01"  # StegoVault signature
    
    def __init__(self):
        self.crypto = CryptoManager()
        self._last_error = None
        self._auto_actions = []  # Track automatic actions taken
    
    def embed_file(self, input_file: str, cover_image: Optional[str] = None, 
                   output_image: str = None, password: Optional[str] = None, 
                   mode: str = 'pixel', compress: bool = False, 
                   quality: int = 95, show_progress: bool = True) -> bool:
        """
        Embed a file into an image
        
        Args:
            input_file: Path to file to embed
            cover_image: Optional cover image (if None, creates new image)
            output_image: Output stego image path
            password: Optional password for encryption
            mode: 'pixel' or 'lsb' (automatically adjusted: LSB for existing images, Pixel for new images)
            compress: Whether to compress data before embedding
            quality: Image quality (1-100)
            show_progress: Show progress bar
        
        Returns:
            bool: True if successful
        """
        try:
            # Clear any previous error and auto-actions
            self._last_error = None
            self._auto_actions = []
            
            # Automatically select mode based on whether cover image is provided
            # - LSB mode: When embedding into existing image (preserves quality)
            # - Pixel mode: When creating new image from scratch
            if cover_image:
                actual_mode = 'lsb'  # Always use LSB for existing images to preserve quality
            else:
                actual_mode = 'pixel'  # Use Pixel mode when creating from scratch
            
            # Read input file
            with open(input_file, 'rb') as f:
                original_file_data = f.read()
            
            file_data = original_file_data
            auto_compressed = False
            
            # If cover image provided, check capacity and auto-enable compression if needed
            if cover_image:
                # Load image to check capacity
                temp_img = Image.open(cover_image)
                temp_img_array = np.array(temp_img)
                temp_height, temp_width = temp_img_array.shape[:2]
                available_bits = temp_height * temp_width * 3
                
                # Try compression first if not already enabled
                test_data = file_data
                if not compress:
                    compressed_test = zlib.compress(test_data, level=9)
                    # Use compression if it reduces size significantly
                    if len(compressed_test) < len(test_data) * 0.95:  # At least 5% reduction
                        test_data = compressed_test
                        auto_compressed = True
                
                # Estimate final payload size after all transformations
                # Metadata: signature(4) + version(1) + file_size(4) + embedded_size(4) + filename_len(1) + filename(up to 255) + hash(32) + flags(2)
                filename_bytes = os.path.basename(input_file).encode('utf-8')
                filename_len = min(len(filename_bytes), 255)
                base_metadata_size = 4 + 1 + 4 + 4 + 1 + filename_len + 32 + 2
                
                # Add encryption overhead if password provided
                if password:
                    # Salt (16) + IV (16) + encryption padding (up to 16 bytes)
                    encryption_overhead = 16 + 16 + 16
                else:
                    encryption_overhead = 0
                
                # Calculate total payload size
                total_payload_size = base_metadata_size + len(test_data) + encryption_overhead
                needed_bits = total_payload_size * 8
                
                # If compression helps and we haven't enabled it yet, enable it
                if auto_compressed and available_bits >= needed_bits:
                    file_data = test_data
                    compress = True
                    self._auto_actions.append("Auto-enabled compression to fit file in image")
                elif auto_compressed:
                    # Compression helps but still not enough - use it anyway
                    file_data = test_data
                    compress = True
                    self._auto_actions.append("Auto-enabled compression (may still be insufficient)")
                    auto_compressed = False  # Reset to allow normal compression path
            
            # Compress if requested (user explicitly enabled or auto-enabled)
            if compress and not auto_compressed:
                file_data = zlib.compress(file_data, level=9)
            
            # Create metadata first (before encryption)
            metadata = self._create_metadata(
                input_file, original_file_data, len(file_data),
                password is not None, compress
            )
            
            # Encrypt if password provided
            salt = None
            iv = None
            if password:
                # Password should already be normalized by caller (GUI/CLI)
                # But ensure it's a string and not empty as a safety check
                if not isinstance(password, str):
                    password = str(password)
                password = password.strip()
                if not password:
                    raise ValueError("Password cannot be empty")
                file_data, salt, iv = self.crypto.encrypt(file_data, password)
                metadata['salt'] = salt
                metadata['iv'] = iv
                metadata['embedded_data_size'] = len(file_data)
            
            # Combine metadata and file data
            payload = self._combine_payload(metadata, file_data)
            
            # Create or load image
            if cover_image:
                original_img = Image.open(cover_image)
                original_img_size = original_img.size
                img = self._embed_pixel(original_img, payload, actual_mode, show_progress)
                # Check if image was resized and add to auto-actions
                if img.size != original_img_size:
                    self._auto_actions.append(f"Auto-resized image from {original_img_size[0]}x{original_img_size[1]} to {img.size[0]}x{img.size[1]} to accommodate file")
            else:
                img = self._create_image_from_data(payload, actual_mode)
            
            # Determine output filename
            if output_image is None:
                base_name = os.path.splitext(os.path.basename(input_file))[0]
                output_image = f"{base_name}_stego.png"
            
            # Ensure output directory exists
            output_dir = os.path.dirname(output_image)
            if output_dir and not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir, exist_ok=True)
                except Exception as e:
                    raise IOError(f"Cannot create output directory {output_dir}: {e}")
            
            # Save image
            output_format = 'PNG' if output_image.lower().endswith('.png') else 'JPEG'
            try:
                if output_format == 'PNG':
                    img.save(output_image, format='PNG', compress_level=9)
                else:
                    img.save(output_image, format='JPEG', quality=quality, progressive=True)
                
                # Verify file was saved
                if not os.path.exists(output_image):
                    raise IOError(f"Failed to save output image: {output_image}")
                
                return True
            except Exception as e:
                # Re-raise with more context
                raise IOError(f"Failed to save image to {output_image}: {e}") from e
        
        except ValueError as e:
            error_msg = str(e)
            print(f"Error: {error_msg}")
            self._last_error = error_msg
            return False
        except FileNotFoundError as e:
            error_msg = f"File not found: {e}"
            print(f"Error: {error_msg}")
            # Store error message for retrieval
            self._last_error = error_msg
            return False
        except PermissionError as e:
            error_msg = f"Permission denied: {e}"
            print(f"Error: {error_msg}")
            self._last_error = error_msg
            return False
        except MemoryError as e:
            error_msg = "Not enough memory - File may be too large. Try using compression."
            print(f"Error: {error_msg}")
            self._last_error = error_msg
            return False
        except IOError as e:
            error_msg = str(e)
            print(f"Error: {error_msg}")
            self._last_error = error_msg
            return False
        except Exception as e:
            import traceback
            error_msg = f"Error embedding file: {e}"
            print(f"Error: {error_msg}")
            print(f"Traceback: {traceback.format_exc()}")
            self._last_error = error_msg
            return False
    
    def extract_file(self, stego_image: str, output_path: Optional[str] = None,
                     password: Optional[str] = None, verify: bool = True) -> Optional[str]:
        """
        Extract file from stego image
        
        Args:
            stego_image: Path to stego image
            output_path: Optional output path (directory or file path)
            password: Password if encrypted
            verify: Verify file integrity
        
        Returns:
            str: Path to extracted file, or None if failed
        """
        try:
            img = Image.open(stego_image)
            
            # Try to extract payload
            payload = None
            
            # Try LSB first (more common)
            try:
                lsb_payload = self._extract_lsb(img)
                if lsb_payload and lsb_payload.startswith(self.SIGNATURE):
                    payload = lsb_payload
            except Exception:
                pass
            
            # Try pixel mode if LSB didn't work
            if not payload:
                try:
                    # Two-stage extraction for pixel mode
                    pixel_payload_sample = self._extract_pixel(img, max_bytes=300)
                    if pixel_payload_sample and len(pixel_payload_sample) >= 5:
                        if pixel_payload_sample.startswith(self.SIGNATURE):
                            # Parse metadata to get exact size
                            temp_metadata = self._parse_metadata(pixel_payload_sample)
                            if temp_metadata:
                                header_size = temp_metadata.get('header_size', 100)
                                embedded_size = temp_metadata.get('embedded_data_size', 
                                                                  temp_metadata.get('file_size', 0))
                                total_size = header_size + embedded_size
                                if total_size > 0:
                                    pixel_payload = self._extract_pixel(img, max_bytes=total_size + 100)
                                    if pixel_payload and pixel_payload.startswith(self.SIGNATURE):
                                        payload = pixel_payload
                except Exception:
                    pass
            
            if not payload or not payload.startswith(self.SIGNATURE):
                raise ValueError("Not a valid stego image")
            
            # Parse metadata
            metadata = self._parse_metadata(payload)
            if not metadata:
                raise ValueError("Failed to parse metadata")
            
            # Extract file data
            header_size = metadata.get('header_size', 100)
            embedded_size = metadata.get('embedded_data_size', metadata.get('file_size', 0))
            
            if len(payload) < header_size + embedded_size:
                raise ValueError("Incomplete payload")
            
            file_data = payload[header_size:header_size + embedded_size]
            
            # Decrypt if needed
            if metadata['encrypted']:
                if not password:
                    raise ValueError("Password required for encrypted file")
                # Password should already be normalized by caller (GUI/CLI)
                # But ensure it's a string and not empty as a safety check
                if not isinstance(password, str):
                    password = str(password)
                password = password.strip()
                if not password:
                    raise ValueError("Password cannot be empty")
                try:
                    file_data = self.crypto.decrypt(
                        file_data,
                        password,
                        metadata['salt'],
                        metadata['iv']
                    )
                except ValueError as e:
                    # Re-raise with clearer message for wrong password
                    error_msg = str(e).lower()
                    if "incorrect password" in error_msg or "password" in error_msg:
                        raise ValueError("Incorrect password") from e
                    raise ValueError(f"Decryption failed: {e}") from e
            
            # Decompress if needed
            if metadata['compressed']:
                file_data = zlib.decompress(file_data)
            
            # Verify integrity
            if verify:
                computed_hash = hashlib.sha256(file_data).digest()
                if computed_hash != metadata['file_hash']:
                    raise ValueError("File integrity check failed - file may be corrupted")
            
            # Determine output path - always use original filename from metadata
            original_filename = metadata['file_name']
            
            if not output_path:
                # No path specified - use original filename
                output_path = original_filename
            elif os.path.isdir(output_path):
                # Directory specified - use original filename in that directory
                output_path = os.path.join(output_path, original_filename)
            else:
                # File path specified - check if it has extension
                # If no extension or wrong extension, use original extension
                specified_ext = os.path.splitext(output_path)[1]
                original_ext = os.path.splitext(original_filename)[1]
                
                if not specified_ext:
                    # No extension specified - add original extension
                    output_path = output_path + original_ext
                elif specified_ext != original_ext:
                    # Wrong extension specified - replace with original extension
                    output_path = os.path.splitext(output_path)[0] + original_ext
            
            # Save extracted file
            os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return output_path
        
        except Exception as e:
            print(f"Error extracting file: {e}")
            return None
    
    def get_metadata(self, stego_image: str, password: Optional[str] = None) -> Optional[Dict]:
        """Get metadata from stego image without extracting file"""
        try:
            img = Image.open(stego_image)
            
            # Try LSB first
            payload = None
            try:
                lsb_payload = self._extract_lsb(img)
                if lsb_payload and lsb_payload.startswith(self.SIGNATURE):
                    payload = lsb_payload
            except Exception:
                pass
            
            # Try pixel mode if LSB didn't work
            if not payload:
                try:
                    pixel_payload_sample = self._extract_pixel(img, max_bytes=300)
                    if pixel_payload_sample and len(pixel_payload_sample) >= 5:
                        if pixel_payload_sample.startswith(self.SIGNATURE):
                            temp_metadata = self._parse_metadata(pixel_payload_sample)
                            if temp_metadata:
                                header_size = temp_metadata.get('header_size', 100)
                                embedded_size = temp_metadata.get('embedded_data_size', 
                                                                  temp_metadata.get('file_size', 0))
                                total_size = header_size + embedded_size
                                if total_size > 0:
                                    pixel_payload = self._extract_pixel(img, max_bytes=total_size + 100)
                                    if pixel_payload and pixel_payload.startswith(self.SIGNATURE):
                                        payload = pixel_payload
                except Exception:
                    pass
            
            if not payload or not payload.startswith(self.SIGNATURE):
                return None
            
            metadata = self._parse_metadata(payload)
            
            # If file is encrypted, password is optional for viewing metadata
            # Password will still be required for extraction
            # We skip password verification here to avoid false negatives
            # The password will be verified during actual extraction
            if metadata and metadata.get('encrypted', False):
                # Password is optional for metadata viewing
                # If provided, we'll note it but won't verify it here
                # Verification happens during extraction where it matters
                pass
            
            return metadata
        
        except ValueError:
            raise  # Re-raise password-related errors
        except Exception:
            return None
    
    def _create_metadata(self, filename: str, original_data: bytes, 
                        embedded_data_size: int, encrypted: bool, compressed: bool) -> Dict:
        """Create metadata dictionary"""
        file_hash = hashlib.sha256(original_data).digest()
        
        metadata = {
            'signature': self.SIGNATURE,
            'version': 1,
            'file_name': os.path.basename(filename),
            'file_size': len(original_data),
            'embedded_data_size': embedded_data_size,
            'file_hash': file_hash,
            'encrypted': encrypted,
            'compressed': compressed,
        }
        
        # Add salt and IV if encrypted
        if encrypted:
            metadata['salt'] = None  # Will be set during embedding
            metadata['iv'] = None
        
        return metadata
    
    def _combine_payload(self, metadata: Dict, file_data: bytes) -> bytes:
        """Combine metadata and file data into payload"""
        # Serialize metadata
        # Use variable-length filename encoding: length (1 byte) + filename (up to 255 bytes)
        filename_bytes = metadata['file_name'].encode('utf-8')
        filename_len = min(len(filename_bytes), 255)
        
        header = self.SIGNATURE
        header += struct.pack('B', metadata['version'])
        header += struct.pack('I', metadata['file_size'])
        header += struct.pack('I', metadata['embedded_data_size'])
        header += struct.pack('B', filename_len)  # Filename length
        header += filename_bytes[:filename_len]  # Filename (variable length)
        header += metadata['file_hash']
        header += struct.pack('B', 1 if metadata['encrypted'] else 0)
        header += struct.pack('B', 1 if metadata['compressed'] else 0)
        
        # Add salt and IV if encrypted
        if metadata['encrypted']:
            header += metadata['salt']
            header += metadata['iv']
        
        metadata['header_size'] = len(header)
        
        return header + file_data
    
    def _parse_metadata(self, payload: bytes) -> Optional[Dict]:
        """Parse metadata from payload"""
        if len(payload) < 5:
            return None
        
        if payload[:4] != self.SIGNATURE:
            return None
        
        try:
            offset = 4
            version = struct.unpack('B', payload[offset:offset+1])[0]
            offset += 1
            file_size = struct.unpack('I', payload[offset:offset+4])[0]
            offset += 4
            embedded_data_size = struct.unpack('I', payload[offset:offset+4])[0]
            offset += 4
            # Read filename length first, then filename
            filename_len = struct.unpack('B', payload[offset:offset+1])[0]
            offset += 1
            file_name = payload[offset:offset+filename_len].decode('utf-8')
            offset += filename_len
            file_hash = payload[offset:offset+32]
            offset += 32
            encrypted = struct.unpack('B', payload[offset:offset+1])[0] == 1
            offset += 1
            compressed = struct.unpack('B', payload[offset:offset+1])[0] == 1
            offset += 1
            
            salt = None
            iv = None
            if encrypted:
                # Ensure we have enough bytes for salt and IV
                if len(payload) < offset + 32:
                    raise ValueError("Incomplete encrypted metadata - missing salt/IV")
                salt = payload[offset:offset+16]
                offset += 16
                iv = payload[offset:offset+16]
                offset += 16
                # Validate salt and IV are not empty
                if not salt or len(salt) != 16:
                    raise ValueError("Invalid salt in metadata")
                if not iv or len(iv) != 16:
                    raise ValueError("Invalid IV in metadata")
            
            metadata = {
                'signature': self.SIGNATURE,
                'version': version,
                'file_name': file_name,
                'file_size': file_size,
                'embedded_data_size': embedded_data_size,
                'file_hash': file_hash,
                'encrypted': encrypted,
                'compressed': compressed,
                'salt': salt,
                'iv': iv,
                'header_size': offset
            }
            
            return metadata
        except Exception:
            return None
    
    def _create_image_from_data(self, data: bytes, mode: str = 'pixel') -> Image.Image:
        """Create a new image from scratch using data"""
        data_len = len(data)
        
        if mode == 'pixel':
            # Calculate size needed: 3 bytes per pixel (RGB)
            pixels_needed = (data_len + 2) // 3
            size = int(np.ceil(np.sqrt(pixels_needed)))
            # Set minimum size to 512x512 for better visibility and quality
            # For very small files, use a reasonable minimum; for larger files, scale appropriately
            size = max(size, 512)  # Minimum 512x512 for good visibility
            
            # Create base image with improved pattern to reduce top edge corruption
            img_array = np.zeros((size, size, 3), dtype=np.uint8)
            
            # Create smoother base pattern with better distribution
            # Use smoother gradients and better color transitions, especially at top edge
            import math
            for y in range(size):
                for x in range(size):
                    # Normalize coordinates to 0-1 range
                    nx = x / size
                    ny = y / size
                    
                    # Create smoother gradients with better transitions
                    # Use sine/cosine for smoother curves, especially at top edge (ny near 0)
                    # Add extra smoothing for top rows to reduce visible corruption
                    top_smoothing = 1.0 - (ny * 0.3)  # More smoothing at top
                    
                    base_r = int(128 + 45 * math.sin(nx * math.pi) * math.cos(ny * math.pi * 0.5) * top_smoothing + 
                                 18 * (nx - 0.5) + 8 * (ny - 0.5))
                    base_g = int(128 + 45 * math.cos(nx * math.pi * 0.5) * math.sin(ny * math.pi) * top_smoothing + 
                                 18 * (ny - 0.5) + 8 * (nx - 0.5))
                    base_b = int(128 + 35 * math.sin((nx + ny) * math.pi * 0.7) * top_smoothing + 
                                 12 * ((nx + ny) / 2 - 0.5))
                    
                    base_r = max(0, min(255, base_r))
                    base_g = max(0, min(255, base_g))
                    base_b = max(0, min(255, base_b))
                    img_array[y, x] = [base_r, base_g, base_b]
            
            # Embed data using a visually pleasing approach
            # Instead of raw data replacement, use LSB embedding on the nice base pattern
            # This creates visually appealing images while maintaining data integrity
            data_bits = []
            for byte in data:
                for i in range(8):
                    data_bits.append((byte >> i) & 1)
            
            # Embed data using LSB on the base pattern for visual appeal
            bit_index = 0
            for y in range(size):
                for x in range(size):
                    if bit_index < len(data_bits):
                        # Embed in LSB of each channel, preserving the nice base pattern
                        for c in range(3):
                            if bit_index < len(data_bits):
                                # Only modify the least significant bit
                                img_array[y, x, c] = (img_array[y, x, c] & 0xFE) | data_bits[bit_index]
                                bit_index += 1
                    else:
                        # No more data to embed, keep the base pattern
                        break
                if bit_index >= len(data_bits):
                    break
            
            return Image.fromarray(img_array)
        
        else:  # LSB mode
            # Calculate size needed: 1 bit per pixel, 3 channels = 3 bits per pixel
            bits_needed = data_len * 8
            pixels_needed = (bits_needed + 2) // 3
            size = int(np.ceil(np.sqrt(pixels_needed)))
            # Set minimum size to 512x512 for better visibility and quality
            size = max(size, 512)  # Minimum 512x512 for good visibility
            
            # Create base image
            img_array = np.zeros((size, size, 3), dtype=np.uint8)
            for y in range(size):
                for x in range(size):
                    base_r = int(128 + (x / size - 0.5) * 60)
                    base_g = int(128 + (y / size - 0.5) * 60)
                    base_b = int(128 + ((x + y) / (size * 2) - 0.5) * 60)
                    img_array[y, x] = [max(0, min(255, base_r)), 
                                        max(0, min(255, base_g)), 
                                        max(0, min(255, base_b))]
            
            # Embed data using LSB
            data_bits = []
            for byte in data:
                for i in range(8):
                    data_bits.append((byte >> i) & 1)
            
            bit_index = 0
            for y in range(size):
                for x in range(size):
                    if bit_index < len(data_bits):
                        # Embed in LSB of each channel
                        for c in range(3):
                            if bit_index < len(data_bits):
                                img_array[y, x, c] = (img_array[y, x, c] & 0xFE) | data_bits[bit_index]
                                bit_index += 1
                    else:
                        break
                if bit_index >= len(data_bits):
                    break
            
            return Image.fromarray(img_array)
    
    def _embed_pixel(self, img: Image.Image, data: bytes, mode: str, show_progress: bool) -> Image.Image:
        """
        Embed data into existing image - preserves image size and quality
        
        Note: This function should only receive 'lsb' mode when called from embed_file(),
        as embed_file() automatically switches to LSB mode when a cover image is provided.
        Pixel mode is only used when creating new images from scratch (no cover image).
        """
        img_array = np.array(img)
        height, width = img_array.shape[:2]
        # Store original size in PIL format: (width, height)
        original_size = img.size  # PIL Image.size is (width, height)
        data_len = len(data)
        
        # Safety check: if pixel mode somehow reaches here, switch to LSB
        # (This shouldn't happen as embed_file() handles mode selection automatically)
        if mode == 'pixel':
            mode = 'lsb'
        
        if mode == 'lsb':
            # LSB mode: Only modify least significant bits to preserve image quality
            # Check capacity and automatically resize if needed to accommodate any file size
            bits_needed = data_len * 8
            pixels_needed = (bits_needed + 2) // 3
            available_pixels = height * width
            available_bits = available_pixels * 3  # 3 channels per pixel
            
            if available_bits < bits_needed:
                # Automatically resize to accommodate the data
                # Calculate new size needed (square image)
                new_size = int(np.ceil(np.sqrt(pixels_needed)))
                # Ensure minimum reasonable size
                new_size = max(new_size, 512)
                
                # Store original size for messaging
                old_size_str = f"{width}x{height}"
                
                # Resize image to accommodate data (use LANCZOS for high quality)
                img = img.resize((new_size, new_size), Image.Resampling.LANCZOS)
                img_array = np.array(img)
                height, width = img_array.shape[:2]
                original_size = (height, width)
                
                # Note: Resize info will be tracked in embed_file() via auto_actions
            
            # Convert data to bits
            data_bits = []
            for byte in data:
                for i in range(8):
                    data_bits.append((byte >> i) & 1)
            
            # Embed using LSB - only modify least significant bit to preserve image quality
            bit_index = 0
            for y in range(height):
                for x in range(width):
                    if bit_index < len(data_bits):
                        for c in range(3):
                            if bit_index < len(data_bits):
                                # Preserve original pixel value, only change LSB
                                img_array[y, x, c] = (img_array[y, x, c] & 0xFE) | data_bits[bit_index]
                                bit_index += 1
                    else:
                        break
                if bit_index >= len(data_bits):
                    break
            
            # Return the result image (size may have changed if auto-resized)
            result_img = Image.fromarray(img_array)
            return result_img
        
        else:
            # Fallback: should not reach here, but handle gracefully
            raise ValueError(f"Unknown mode: {mode}")
    
    def _extract_pixel(self, img: Image.Image, max_bytes: Optional[int] = None) -> bytes:
        """Extract data using pixel-based method"""
        img_array = np.array(img)
        height, width = img_array.shape[:2]
        
        data = bytearray()
        total_pixels = height * width
        
        if max_bytes is not None:
            pixels_to_read = min((max_bytes + 2) // 3, total_pixels)
        else:
            pixels_to_read = total_pixels
        
        pixels_read = 0
        for y in range(height):
            for x in range(width):
                if pixels_read >= pixels_to_read:
                    break
                pixel = img_array[y, x]
                data.extend(pixel[:3])
                pixels_read += 1
            if pixels_read >= pixels_to_read:
                break
        
        return bytes(data)
    
    def _extract_lsb(self, img: Image.Image) -> bytes:
        """Extract data using LSB method"""
        img_array = np.array(img)
        height, width = img_array.shape[:2]
        
        # Extract all LSBs
        data_bits = []
        for y in range(height):
            for x in range(width):
                for c in range(3):
                    bit = img_array[y, x, c] & 1
                    data_bits.append(bit)
        
        # Convert bits to bytes
        result = bytearray()
        for i in range(0, len(data_bits), 8):
            if i + 8 > len(data_bits):
                break
            byte = 0
            for j in range(8):
                byte |= (data_bits[i + j] << j)
            result.append(byte)
        
        return bytes(result)

