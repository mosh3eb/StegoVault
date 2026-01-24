"""
Core steganography engine for embedding and extracting files
"""

import os
import struct
import zlib
import hashlib
from typing import Optional, Dict, List
from PIL import Image
import numpy as np
from .crypto import CryptoManager
from .archive import ArchiveManager
from .robustness import RobustnessEngine
from .steganalysis import SteganalysisProtection
from .metadata import MetadataManager
from .capacity import CapacityManager


class StegoEngine:
    """Main steganography engine"""
    
    SIGNATURE = b"SV01"  # StegoVault signature
    
    def __init__(self, enable_robustness: bool = False, 
                 enable_anti_steganalysis: bool = False,
                 robustness_level: int = 2):
        """
        Initialize steganography engine
        
        Args:
            enable_robustness: Enable social media robustness features
            enable_anti_steganalysis: Enable anti-steganalysis protection
            robustness_level: Redundancy level (1-5) for robustness
        """
        self.crypto = CryptoManager()
        self.archive = ArchiveManager()
        self.robustness = RobustnessEngine(redundancy_level=robustness_level) if enable_robustness else None
        # Always create SteganalysisProtection so detection features are available,
        # but gate anti-steganalysis embedding behavior behind the flag.
        self.steganalysis = SteganalysisProtection()
        self.metadata = MetadataManager()
        self.capacity = CapacityManager()
        self._last_error = None
        self._auto_actions = []  # Track automatic actions taken
        self._enable_robustness = enable_robustness
        self._enable_anti_steganalysis = enable_anti_steganalysis
    
    def embed_file(self, input_file: str, cover_image: Optional[str] = None, 
                   output_image: str = None, password: Optional[str] = None, 
                   mode: str = 'pixel', compress: bool = False, 
                   quality: int = 95, show_progress: bool = True,
                   is_archive: bool = False,
                   strip_metadata: bool = False,
                   enable_robustness: Optional[bool] = None,
                   enable_anti_steganalysis: Optional[bool] = None) -> bool:
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
            
            # Apply robustness features if enabled
            had_ecc = False
            had_redundancy = False
            if (enable_robustness if enable_robustness is not None else self._enable_robustness) and self.robustness:
                file_data = self.robustness.prepare_for_social_media(file_data, enable_ecc=True, enable_redundancy=True)
                had_ecc = True
                had_redundancy = True
                self._auto_actions.append("Applied robustness features for social media sharing")
            
            # Create metadata first (before encryption)
            metadata = self._create_metadata(
                input_file, original_file_data, len(file_data),
                password is not None, compress, is_archive, had_ecc, had_redundancy
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
            
            # Strip metadata from cover image if requested
            if strip_metadata and cover_image:
                try:
                    cover_image = self.metadata.strip_metadata(cover_image)
                    self._auto_actions.append("Stripped metadata from cover image")
                except Exception:
                    pass  # Continue if metadata stripping fails
            
            # Create or load image
            if cover_image:
                original_img = Image.open(cover_image)
                original_img_size = original_img.size
                
                # Apply anti-steganalysis protection if enabled
                if (enable_anti_steganalysis if enable_anti_steganalysis is not None else self._enable_anti_steganalysis) and self.steganalysis:
                    # Analyze cover image for safe pixel selection
                    analysis = self.steganalysis.analyze_cover_image(original_img)
                    img = self._embed_pixel_adaptive(original_img, payload, actual_mode, show_progress, analysis)
                    self._auto_actions.append("Applied anti-steganalysis protection")
                else:
                    img = self._embed_pixel(original_img, payload, actual_mode, show_progress)
                
                # Check if image was resized and add to auto-actions
                if img.size != original_img_size:
                    self._auto_actions.append(f"Auto-resized image from {original_img_size[0]}x{original_img_size[1]} to {img.size[0]}x{img.size[1]} to accommodate file")
                
                # Preserve histogram if anti-steganalysis is enabled
                if (enable_anti_steganalysis if enable_anti_steganalysis is not None else self._enable_anti_steganalysis) and self.steganalysis:
                    img = self.steganalysis.preserve_histogram(original_img, img)
            else:
                img = self._create_image_from_data(payload, actual_mode)
            
            # Determine output filename - always PNG
            if output_image is None:
                base_name = os.path.splitext(os.path.basename(input_file))[0]
                output_image = f"{base_name}_stego.png"
            else:
                # Ensure output is PNG format
                if not output_image.lower().endswith('.png'):
                    output_image = os.path.splitext(output_image)[0] + '.png'
            
            # Ensure output directory exists
            output_dir = os.path.dirname(output_image)
            if output_dir and not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir, exist_ok=True)
                except Exception as e:
                    raise IOError(f"Cannot create output directory {output_dir}: {e}")
            
            # Save image as PNG
            try:
                img.save(output_image, format='PNG', compress_level=9)
                
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
            
            # Verify image format - only PNG is supported
            img_format = img.format
            if img_format != 'PNG' and not stego_image.lower().endswith('.png'):
                raise ValueError("Only PNG format is supported. Please use a PNG image.")
            
            # Ensure RGB mode for consistent extraction
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Try to extract payload
            payload = None
            
            # Try LSB first (more efficient and reliable for PNG)
            try:
                lsb_payload = self._extract_lsb(img)
                if lsb_payload:
                    # PNG - exact match
                    if lsb_payload.startswith(self.SIGNATURE):
                        payload = lsb_payload
            except Exception as e:
                print(f"LSB extraction error: {e}")
                pass
            
            # Try pixel mode if LSB didn't work
            if not payload:
                try:
                    # Two-stage extraction for pixel mode
                    pixel_payload_sample = self._extract_pixel(img, max_bytes=300)
                    if pixel_payload_sample and len(pixel_payload_sample) >= 5:
                        # PNG - exact signature match
                        if pixel_payload_sample.startswith(self.SIGNATURE):
                            # Parse metadata to get exact size
                            temp_metadata = self._parse_metadata(pixel_payload_sample, fuzzy=False)
                            if temp_metadata and self._validate_metadata(temp_metadata):
                                header_size = temp_metadata.get('header_size', 100)
                                embedded_size = temp_metadata.get('embedded_data_size', 
                                                                  temp_metadata.get('file_size', 0))
                                # Account for encryption and robustness overhead
                                encryption_overhead = 50 if temp_metadata.get('encrypted', False) else 0
                                robustness_overhead = 200 if (temp_metadata.get('had_ecc', False) or 
                                                              temp_metadata.get('had_redundancy', False)) else 0
                                total_size = header_size + embedded_size + encryption_overhead + robustness_overhead
                                if total_size > 0:
                                    # Extract with buffer
                                    pixel_payload = self._extract_pixel(img, max_bytes=int(total_size * 1.3))
                                    if pixel_payload and pixel_payload.startswith(self.SIGNATURE):
                                        payload = pixel_payload
                except Exception as e:
                    import traceback
                    print(f"Pixel extraction error: {e}")
                    pass
            
            # Final check
            if not payload:
                raise ValueError("Not a valid stego image")
            
            # Verify signature
            if not payload.startswith(self.SIGNATURE):
                raise ValueError("Not a valid stego image - signature mismatch")
            
            # Parse metadata - exact parsing for PNG
            metadata = self._parse_metadata(payload, fuzzy=False)
            
            if not metadata:
                raise ValueError("Failed to parse metadata")
            
            # Extract file data
            header_size = metadata.get('header_size', 100)
            embedded_size = metadata.get('embedded_data_size', metadata.get('file_size', 0))
            
            # Account for encryption padding and robustness overhead
            # embedded_size already includes encryption padding, but we need to account for robustness
            robustness_overhead = 0
            if metadata.get('had_ecc', False) or metadata.get('had_redundancy', False):
                # Robustness adds overhead - estimate based on redundancy level
                redundancy_level = 2  # Default
                robustness_overhead = embedded_size * redundancy_level  # Rough estimate
            
            # Check if we have enough data
            required_size = header_size + embedded_size + robustness_overhead
            # Use the actual embedded_size from metadata (which includes encryption padding)
            # But check against what we actually have
            if len(payload) < header_size + embedded_size:
                # Try to get more data - might be LSB extraction issue
                # Re-extract with larger buffer
                try:
                    img = Image.open(stego_image)
                    # Try LSB extraction again with full image
                    if metadata.get('had_ecc', False) or metadata.get('had_redundancy', False):
                        # If robustness was used, we need more data
                        larger_payload = self._extract_lsb(img)
                        if larger_payload and len(larger_payload) >= len(payload):
                            payload = larger_payload
                    else:
                        # Try extracting more bytes
                        larger_payload = self._extract_lsb(img)
                        if larger_payload and len(larger_payload) > len(payload):
                            payload = larger_payload
                except Exception:
                    pass
                
                # Check again after re-extraction
                if len(payload) < header_size + embedded_size:
                    # Provide helpful error message
                    error_msg = f"Incomplete payload: got {len(payload)} bytes, need {header_size + embedded_size} bytes"
                    error_msg += f"\nHeader: {header_size} bytes, Data: {embedded_size} bytes"
                    
                    if metadata.get('encrypted', False):
                        error_msg += "\nFile is encrypted - ensure password is correct"
                    if metadata.get('had_ecc', False) or metadata.get('had_redundancy', False):
                        error_msg += "\nRobustness features were used - try enabling robustness recovery"
                    raise ValueError(error_msg)
            
            file_data = payload[header_size:header_size + embedded_size]
            
            # Verify we got the right amount
            if len(file_data) < embedded_size:
                raise ValueError(f"Incomplete file data: got {len(file_data)} bytes, expected {embedded_size} bytes")
            
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
            
            # Apply robustness recovery if needed
            had_ecc = metadata.get('had_ecc', False)
            had_redundancy = metadata.get('had_redundancy', False)
            if had_ecc or had_redundancy:
                # Create robustness engine if needed (even if not enabled during init)
                if not self.robustness:
                    self.robustness = RobustnessEngine(redundancy_level=2)
                try:
                    file_data, errors = self.robustness.recover_from_social_media(
                        file_data, had_ecc=had_ecc, had_redundancy=had_redundancy
                    )
                    if errors > 0:
                        self._auto_actions.append(f"Recovered {errors} errors using robustness features")
                except Exception as e:
                    # If recovery fails, continue without it
                    pass
            
            # Decompress if needed
            if metadata['compressed']:
                file_data = zlib.decompress(file_data)
            
            # Verify integrity
            if verify:
                computed_hash = hashlib.sha256(file_data).digest()
                if computed_hash != metadata['file_hash']:
                    # For PNG, integrity failure is a real problem
                    raise ValueError("File integrity check failed - file may be corrupted")
            
            # Determine output path - always use original filename from metadata
            original_filename = metadata['file_name']
            
            # Sanitize filename to remove null bytes and invalid characters
            original_filename = self._sanitize_filename(original_filename)
            
            # Detect if filename is generic/corrupted (like "recovered_file", "file", etc.)
            generic_filenames = {'recovered_file', 'file', 'extracted_file', 'output', 'data'}
            is_generic_filename = (os.path.splitext(original_filename)[0].lower() in generic_filenames or 
                                  len(os.path.splitext(original_filename)[0]) == 0)
            
            original_ext = os.path.splitext(original_filename)[1]
            
            # Detect extension if extension is missing or filename is generic/corrupted
            if len(file_data) > 0 and (not original_ext or is_generic_filename):
                detected_ext = self._detect_file_extension(file_data)
                if detected_ext:
                    # If no extension or generic filename, use detected extension
                    if not original_ext:
                        original_filename = original_filename + detected_ext
                        original_ext = detected_ext
                    elif is_generic_filename:
                        # For generic/corrupted filenames, prefer detected extension over metadata
                        # Replace extension if different, or add if missing
                        if original_ext != detected_ext:
                            # Remove old extension and add detected one
                            base_name = os.path.splitext(original_filename)[0]
                            original_filename = base_name + detected_ext
                            original_ext = detected_ext
            
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
                
                if not specified_ext:
                    # No extension specified - add original extension
                    if original_ext:
                        output_path = output_path + original_ext
                    else:
                        # Try to detect from file data as fallback
                        detected_ext = self._detect_file_extension(file_data)
                        if detected_ext:
                            output_path = output_path + detected_ext
                elif specified_ext != original_ext and original_ext:
                    # Wrong extension specified - replace with original extension
                    output_path = os.path.splitext(output_path)[0] + original_ext
            
            # Save extracted file
            os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return output_path
        
        except ValueError as e:
            # Password errors and validation errors - store for retrieval
            error_msg = str(e)
            self._last_error = error_msg
            print(f"Error extracting file: {e}")
            return None
        except FileNotFoundError as e:
            error_msg = f"File not found: {e}"
            self._last_error = error_msg
            print(f"Error: {error_msg}")
            return None
        except PermissionError as e:
            error_msg = f"Permission denied: {e}"
            self._last_error = error_msg
            print(f"Error: {error_msg}")
            return None
        except Exception as e:
            import traceback
            error_msg = f"Error extracting file: {e}"
            self._last_error = error_msg
            print(f"Error extracting file: {e}")
            print(f"Traceback: {traceback.format_exc()}")
            return None
    
    def get_metadata(self, stego_image: str, password: Optional[str] = None) -> Optional[Dict]:
        """Get metadata from stego image without extracting file"""
        try:
            img = Image.open(stego_image)
            
            # Verify image format - only PNG is supported
            img_format = img.format
            if img_format != 'PNG' and not stego_image.lower().endswith('.png'):
                return None  # Not a PNG image
            
            # Try LSB first
            payload = None
            try:
                lsb_payload = self._extract_lsb(img)
                if lsb_payload:
                    if lsb_payload.startswith(self.SIGNATURE):
                        payload = lsb_payload
            except Exception:
                pass
            
            # Try pixel mode if LSB didn't work
            if not payload:
                try:
                    pixel_payload_sample = self._extract_pixel(img, max_bytes=300)
                    if pixel_payload_sample and len(pixel_payload_sample) >= 5:
                        if pixel_payload_sample.startswith(self.SIGNATURE):
                            temp_metadata = self._parse_metadata(pixel_payload_sample, fuzzy=False)
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
            
            if not payload:
                return None
            
            # Verify signature
            if not payload.startswith(self.SIGNATURE):
                return None
            
            # Parse metadata - exact parsing for PNG
            metadata = self._parse_metadata(payload, fuzzy=False)
            
            if not metadata:
                return None
            
            # If file is encrypted, password is optional for viewing metadata
            # Password will still be required for extraction
            # We skip password verification here to avoid false negatives
            # The password will be verified during actual extraction
            if metadata.get('encrypted', False):
                # Password is optional for metadata viewing
                # If provided, we'll note it but won't verify it here
                # Verification happens during extraction where it matters
                pass
            
            return metadata
        
        except ValueError:
            raise  # Re-raise password-related errors
        except Exception:
            return None
    
    def _parse_metadata_minimal(self, payload: bytes) -> Optional[Dict]:
        """
        Parse metadata with minimal requirements - last resort for corrupted data
        
        Returns minimal metadata with defaults for corrupted fields
        """
        if len(payload) < 20:  # Need at least some data
            return None
        
        try:
            offset = 4  # Skip signature
            
            # Try to parse minimal fields with very tolerant error handling
            version = 1
            if offset + 1 <= len(payload):
                try:
                    version = struct.unpack('B', payload[offset:offset+1])[0]
                    if version > 10:  # Sanity check
                        version = 1
                except:
                    version = 1
            offset += 1
            
            # Try to get file size (but don't fail if corrupted)
            file_size = 0
            embedded_data_size = 0
            if offset + 8 <= len(payload):
                try:
                    file_size = struct.unpack('I', payload[offset:offset+4])[0]
                    if file_size > 1000000000:  # Sanity check
                        file_size = 0
                except:
                    file_size = 0
                offset += 4
                
                try:
                    embedded_data_size = struct.unpack('I', payload[offset:offset+4])[0]
                    if embedded_data_size > 1000000000:  # Sanity check
                        embedded_data_size = file_size if file_size > 0 else 0
                except:
                    embedded_data_size = file_size if file_size > 0 else 0
                offset += 4
            
            # Try to get filename (very tolerant)
            file_name = "recovered_file"
            if offset + 1 <= len(payload):
                try:
                    filename_len = struct.unpack('B', payload[offset:offset+1])[0]
                    if filename_len > 255 or filename_len < 0:
                        filename_len = min(50, len(payload) - offset - 1)
                    offset += 1
                    
                    if offset + filename_len <= len(payload):
                        try:
                            file_name = payload[offset:offset+filename_len].decode('utf-8', errors='replace')
                            if not file_name or len(file_name.strip()) == 0:
                                file_name = "recovered_file"
                        except:
                            file_name = "recovered_file"
                        # Sanitize filename to remove null bytes and invalid characters
                        file_name = self._sanitize_filename(file_name)
                        offset += filename_len
                except:
                    pass
            
            # Skip hash (32 bytes)
            if offset + 32 <= len(payload):
                file_hash = payload[offset:offset+32]
                offset += 32
            else:
                file_hash = b'\x00' * 32
            
            # Try to get flags (very tolerant)
            encrypted = False
            compressed = False
            if offset + 2 <= len(payload):
                try:
                    encrypted = struct.unpack('B', payload[offset:offset+1])[0] == 1
                except:
                    encrypted = False
                offset += 1
                
                try:
                    compressed = struct.unpack('B', payload[offset:offset+1])[0] == 1
                except:
                    compressed = False
                offset += 1
            
            # Estimate header size
            header_size = offset
            
            # Create minimal metadata
            metadata = {
                'signature': self.SIGNATURE,
                'version': version,
                'file_name': file_name,
                'file_size': file_size if file_size > 0 else embedded_data_size,
                'embedded_data_size': embedded_data_size if embedded_data_size > 0 else file_size,
                'file_hash': file_hash,
                'encrypted': encrypted,
                'compressed': compressed,
                'salt': None,
                'iv': None,
                'header_size': header_size,
                'is_archive': False,
                'had_ecc': False,
                'had_redundancy': False
            }
            
            return metadata
        except Exception as e:
            print(f"Minimal metadata parsing failed: {e}")
            return None
    
    def _create_metadata(self, filename: str, original_data: bytes, 
                        embedded_data_size: int, encrypted: bool, compressed: bool,
                        is_archive: bool = False, had_ecc: bool = False, 
                        had_redundancy: bool = False) -> Dict:
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
            'is_archive': is_archive,
            'had_ecc': had_ecc,
            'had_redundancy': had_redundancy,
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
        header += struct.pack('B', 1 if metadata.get('is_archive', False) else 0)
        header += struct.pack('B', 1 if metadata.get('had_ecc', False) else 0)
        header += struct.pack('B', 1 if metadata.get('had_redundancy', False) else 0)
        
        # Add salt and IV if encrypted
        if metadata['encrypted']:
            header += metadata['salt']
            header += metadata['iv']
        
        metadata['header_size'] = len(header)
        
        return header + file_data
    
    def _parse_metadata(self, payload: bytes, fuzzy: bool = False) -> Optional[Dict]:
        """
        Parse metadata from payload
        
        Args:
            payload: Payload bytes starting with signature
            fuzzy: If True, tolerate small errors (not used for PNG)
        """
        if len(payload) < 5:
            return None
        
        # Check signature
        if fuzzy:
            if not self._fuzzy_signature_match(payload[:4], self.SIGNATURE, max_errors=2):
                return None
        else:
            if payload[:4] != self.SIGNATURE:
                return None
        
        try:
            offset = 4
            
            # Parse version with error tolerance
            if offset + 1 > len(payload):
                raise ValueError("Incomplete metadata: missing version")
            try:
                version_byte = struct.unpack('B', payload[offset:offset+1])[0]
                # Validate version - should be 1 (current version)
                # For fuzzy parsing, allow small variations but reject clearly wrong values
                if fuzzy:
                    if version_byte > 10:  # Version should be 1, reject if > 10 (likely corruption)
                        # Try to recover by using default
                        version = 1
                        print(f"Warning: Invalid version byte ({version_byte}), using default version 1")
                    else:
                        version = version_byte
                else:
                    if version_byte != 1:
                        raise ValueError(f"Invalid version: {version_byte} (expected 1)")
                    version = version_byte
            except Exception as e:
                if fuzzy:
                    version = 1  # Default version
                    print(f"Warning: Failed to parse version, using default: {e}")
                else:
                    raise ValueError(f"Failed to parse version: {e}")
            offset += 1
            
            # Parse file_size with error tolerance
            if offset + 4 > len(payload):
                raise ValueError("Incomplete metadata: missing file_size")
            try:
                file_size = struct.unpack('I', payload[offset:offset+4])[0]
                # Sanity check
                if file_size > 1000000000:  # 1GB max
                    if fuzzy:
                        file_size = 0  # Will be set from embedded_data_size
                    else:
                        raise ValueError(f"Invalid file_size: {file_size}")
            except Exception as e:
                if fuzzy:
                    file_size = 0  # Will try to recover from embedded_data_size
                else:
                    raise ValueError(f"Failed to parse file_size: {e}")
            offset += 4
            
            # Parse embedded_data_size
            if offset + 4 > len(payload):
                raise ValueError("Incomplete metadata: missing embedded_data_size")
            try:
                embedded_data_size = struct.unpack('I', payload[offset:offset+4])[0]
                # Sanity check
                if embedded_data_size > 1000000000:  # 1GB max
                    if fuzzy:
                        embedded_data_size = 0
                    else:
                        raise ValueError(f"Invalid embedded_data_size: {embedded_data_size}")
                # Use embedded_data_size as file_size if file_size is invalid
                if file_size == 0 and embedded_data_size > 0:
                    file_size = embedded_data_size
            except Exception as e:
                if fuzzy:
                    embedded_data_size = file_size if file_size > 0 else 0
                else:
                    raise ValueError(f"Failed to parse embedded_data_size: {e}")
            offset += 4
            
            # Read filename length first, then filename
            if offset + 1 > len(payload):
                raise ValueError("Incomplete metadata: missing filename_len")
            try:
                filename_len = struct.unpack('B', payload[offset:offset+1])[0]
                # Sanity check filename length
                if filename_len > 255 or filename_len < 0:
                    if fuzzy:
                        filename_len = min(50, len(payload) - offset - 1)  # Reasonable default
                    else:
                        raise ValueError(f"Invalid filename length: {filename_len}")
            except Exception as e:
                if fuzzy:
                    filename_len = min(50, len(payload) - offset - 1)
                else:
                    raise ValueError(f"Failed to parse filename_len: {e}")
            offset += 1
            
            # Read filename with error tolerance
            if offset + filename_len > len(payload):
                if fuzzy:
                    filename_len = len(payload) - offset
                else:
                    raise ValueError("Incomplete metadata: missing filename")
            try:
                file_name = payload[offset:offset+filename_len].decode('utf-8', errors='replace')
            except Exception as e:
                if fuzzy:
                    # Try to recover filename
                    file_name = payload[offset:offset+filename_len].decode('utf-8', errors='ignore')
                    if not file_name or len(file_name.strip()) == 0:
                        file_name = "recovered_file"
                else:
                    raise ValueError(f"Failed to decode filename: {e}")
            
            # Sanitize filename to remove null bytes and invalid characters (especially important for corrupted JPEG metadata)
            file_name = self._sanitize_filename(file_name)
            
            offset += filename_len
            
            # Read file hash
            if offset + 32 > len(payload):
                if fuzzy:
                    # Use available bytes, pad with zeros
                    available = len(payload) - offset
                    file_hash = payload[offset:offset+available] + b'\x00' * (32 - available)
                else:
                    raise ValueError("Incomplete metadata: missing file_hash")
            else:
                file_hash = payload[offset:offset+32]
            offset += 32
            
            # Parse encrypted flag
            if offset + 1 > len(payload):
                if fuzzy:
                    encrypted = False  # Default to not encrypted if can't read
                else:
                    raise ValueError("Incomplete metadata: missing encrypted flag")
            else:
                try:
                    encrypted = struct.unpack('B', payload[offset:offset+1])[0] == 1
                except Exception as e:
                    if fuzzy:
                        encrypted = False  # Default to not encrypted
                    else:
                        raise ValueError(f"Failed to parse encrypted flag: {e}")
            offset += 1
            
            # Parse compressed flag
            if offset + 1 > len(payload):
                if fuzzy:
                    compressed = False  # Default to not compressed
                else:
                    raise ValueError("Incomplete metadata: missing compressed flag")
            else:
                try:
                    compressed = struct.unpack('B', payload[offset:offset+1])[0] == 1
                except Exception as e:
                    if fuzzy:
                        compressed = False  # Default to not compressed
                    else:
                        raise ValueError(f"Failed to parse compressed flag: {e}")
            offset += 1
            
            # Read new metadata fields (version 2+)
            is_archive = False
            had_ecc = False
            had_redundancy = False
            if len(payload) > offset:
                try:
                    is_archive = struct.unpack('B', payload[offset:offset+1])[0] == 1
                    offset += 1
                    had_ecc = struct.unpack('B', payload[offset:offset+1])[0] == 1
                    offset += 1
                    had_redundancy = struct.unpack('B', payload[offset:offset+1])[0] == 1
                    offset += 1
                except Exception:
                    # Old format, no additional fields
                    pass
            
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
                'header_size': offset,
                'is_archive': is_archive,
                'had_ecc': had_ecc,
                'had_redundancy': had_redundancy
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
    
    def _embed_pixel_adaptive(self, img: Image.Image, data: bytes, mode: str, 
                             show_progress: bool, analysis: Dict) -> Image.Image:
        """
        Embed data using adaptive pixel selection for anti-steganalysis
        
        Args:
            img: Cover image
            data: Data to embed
            mode: Embedding mode
            show_progress: Show progress
            analysis: Image analysis results from steganalysis module
        
        Returns:
            Image: Stego image
        """
        img_array = np.array(img)
        height, width = img_array.shape[:2]
        data_len = len(data)
        
        if mode == 'pixel':
            mode = 'lsb'  # Always use LSB for adaptive embedding
        
        if mode == 'lsb':
            bits_needed = data_len * 8
            available_bits = height * width * 3
            
            if available_bits < bits_needed:
                # Resize if needed
                pixels_needed = (bits_needed + 2) // 3
                new_size = int(np.ceil(np.sqrt(pixels_needed)))
                new_size = max(new_size, 512)
                img = img.resize((new_size, new_size), Image.Resampling.LANCZOS)
                img_array = np.array(img)
                height, width = img_array.shape[:2]
            
            # Convert data to bits
            data_bits = []
            for byte in data:
                for i in range(8):
                    data_bits.append((byte >> i) & 1)
            
            # Select safe pixels using anti-steganalysis
            if self.steganalysis:
                safe_pixels = self.steganalysis.select_safe_pixels(img_array, len(data_bits), analysis)
                
                # Embed using safe pixels
                for bit_index, (y, x, c) in enumerate(safe_pixels):
                    if bit_index < len(data_bits):
                        img_array[y, x, c] = (img_array[y, x, c] & 0xFE) | data_bits[bit_index]
            else:
                # Fallback to regular embedding
                bit_index = 0
                for y in range(height):
                    for x in range(width):
                        if bit_index < len(data_bits):
                            for c in range(3):
                                if bit_index < len(data_bits):
                                    img_array[y, x, c] = (img_array[y, x, c] & 0xFE) | data_bits[bit_index]
                                    bit_index += 1
                        else:
                            break
                    if bit_index >= len(data_bits):
                        break
            
            return Image.fromarray(img_array)
        else:
            # Fallback to regular embedding
            return self._embed_pixel(img, data, mode, show_progress)
    
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
    
    def _detect_file_extension(self, file_data: bytes) -> Optional[str]:
        """
        Detect file extension from file data using magic bytes/file signatures
        
        Args:
            file_data: File data bytes
            
        Returns:
            str: File extension (e.g., '.pdf', '.txt') or None if not detected
        """
        if len(file_data) < 4:
            return None
        
        # Check magic bytes for common file types
        # PDF
        if file_data[:4] == b'%PDF':
            return '.pdf'
        
        # ZIP (also covers .docx, .xlsx, .pptx, etc.)
        if file_data[:2] == b'PK':
            return '.zip'
        
        # PNG
        if file_data[:8] == b'\x89PNG\r\n\x1a\n':
            return '.png'
        
        
        # GIF
        if file_data[:6] in (b'GIF87a', b'GIF89a'):
            return '.gif'
        
        # BMP
        if file_data[:2] == b'BM':
            return '.bmp'
        
        # TIFF
        if file_data[:4] in (b'II*\x00', b'MM\x00*'):
            return '.tiff'
        
        # MP3 (ID3v2 or MPEG frame sync)
        if file_data[:3] == b'ID3' or (len(file_data) >= 2 and file_data[:2] == b'\xff\xfb'):
            return '.mp3'
        
        # MP4/MOV (ftyp box)
        if len(file_data) >= 12 and file_data[4:8] == b'ftyp':
            return '.mp4'
        
        # AVI
        if file_data[:4] == b'RIFF' and len(file_data) >= 8 and file_data[8:12] == b'AVI ':
            return '.avi'
        
        # Windows executable
        if file_data[:2] == b'MZ':
            return '.exe'
        
        # ELF executable
        if file_data[:4] == b'\x7fELF':
            return ''
        
        # Text files (check if it's valid UTF-8 text)
        try:
            # Try to decode as UTF-8
            text = file_data[:1024].decode('utf-8')
            # Check if it looks like text (mostly printable characters)
            if all(ord(c) < 128 and (c.isprintable() or c in '\n\r\t') for c in text[:100]):
                return '.txt'
        except (UnicodeDecodeError, AttributeError):
            pass
        
        # If no match found, return None
        return None
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to remove null bytes and invalid path characters
        
        Args:
            filename: Original filename (may contain null bytes or invalid chars)
            
        Returns:
            str: Sanitized filename safe for use in file paths
        """
        if not filename:
            return "extracted_file"
        
        # Remove null bytes and other control characters
        # Replace null bytes and other problematic characters
        sanitized = filename.replace('\x00', '').replace('\0', '')
        
        # Remove other control characters (except newline, tab, carriage return which are sometimes OK in filenames)
        # But for safety, remove all control characters
        sanitized = ''.join(c for c in sanitized if ord(c) >= 32 or c in '\n\r\t')
        
        # Check if filename is too corrupted (has too many non-ASCII or non-printable characters)
        # Count printable ASCII characters
        printable_ascii_count = sum(1 for c in sanitized if c.isprintable() and ord(c) < 128)
        total_chars = len(sanitized)
        
        # If less than 50% are printable ASCII, or if it contains too many weird characters, consider it corrupted
        if total_chars > 0:
            printable_ratio = printable_ascii_count / total_chars
            # Also check for excessive non-ASCII characters that might be corruption artifacts
            non_ascii_count = sum(1 for c in sanitized if ord(c) >= 128)
            
            # If filename is mostly non-printable or has excessive non-ASCII corruption, use default
            if printable_ratio < 0.5 or (non_ascii_count > 10 and printable_ratio < 0.7):
                return "extracted_file"
        
        # Remove invalid path characters (OS-dependent, but common ones)
        invalid_chars = '<>:"|?*\\'
        for char in invalid_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Remove leading/trailing spaces and dots (can cause issues on Windows)
        sanitized = sanitized.strip(' .')
        
        # If filename is empty after sanitization, use a default
        if not sanitized or len(sanitized.strip()) == 0:
            sanitized = "extracted_file"
        
        # Check if the filename looks reasonable (not just random characters)
        # If it's too short or doesn't look like a real filename, use default
        if len(sanitized) < 3:
            sanitized = "extracted_file"
        
        # Limit filename length (some systems have limits)
        if len(sanitized) > 255:
            # Keep extension if present
            name, ext = os.path.splitext(sanitized)
            max_name_len = 255 - len(ext)
            sanitized = name[:max_name_len] + ext
        
        return sanitized
    
    def _validate_metadata(self, metadata: Dict) -> bool:
        """
        Validate that parsed metadata makes sense
        
        Args:
            metadata: Parsed metadata dictionary
            
        Returns:
            bool: True if metadata appears valid, False otherwise
        """
        if not metadata:
            return False
        
        # Check version - should be 1
        version = metadata.get('version', 0)
        if version != 1:
            return False
        
        # Check file sizes - should be reasonable
        file_size = metadata.get('file_size', 0)
        embedded_size = metadata.get('embedded_data_size', 0)
        
        # Both shouldn't be 0 (unless it's a very small file, but even then embedded_size should be > 0)
        if file_size == 0 and embedded_size == 0:
            return False
        
        # File sizes should be reasonable (not too large)
        if file_size > 1000000000 or embedded_size > 1000000000:  # 1GB max
            return False
        
        # Filename should exist and be reasonable
        filename = metadata.get('file_name', '')
        if not filename or len(filename) == 0:
            return False
        
        # Filename shouldn't be just the default (unless it was actually named that)
        if filename == "extracted_file" and file_size > 0:
            # This might be OK if it was actually named extracted_file, but suspicious
            pass
        
        # Header size should be reasonable (at least 20 bytes for minimal metadata)
        header_size = metadata.get('header_size', 0)
        if header_size < 20 or header_size > 1000:
            return False
        
        return True
    
    def _fuzzy_signature_match(self, data: bytes, signature: bytes, max_errors: int = 2) -> bool:
        """
        Check if data starts with signature, allowing for small errors
        
        Args:
            data: Data to check
            signature: Signature to match
            max_errors: Maximum number of bit errors allowed
        
        Returns:
            bool: True if signature matches within tolerance
        """
        if len(data) < len(signature):
            return False
        
        # Exact match first (fast path)
        if data[:len(signature)] == signature:
            return True
        
        # Fuzzy match: count bit differences
        total_bit_errors = 0
        byte_errors = 0
        exact_matches = 0
        
        for i in range(len(signature)):
            byte_diff = data[i] ^ signature[i]
            if byte_diff == 0:
                exact_matches += 1
            else:
                # Count different bits
                bit_errors = bin(byte_diff).count('1')
                total_bit_errors += bit_errors
                byte_errors += 1
        
        # Very tolerant matching:
        # - Allow if at least 2 bytes match exactly (out of 4)
        # - OR if total bit errors are reasonable
        # - OR if byte errors are within limit
        if exact_matches >= 2:
            return True
        
        # Allow reasonable bit errors (more tolerant for higher max_errors)
        if total_bit_errors <= max_errors * 8:
            return True
        
        # Allow if only 1-2 bytes differ (very tolerant)
        if byte_errors <= max_errors:
            return True
        
        return False
    
    def _find_signature_in_data(self, data: bytes, signature: bytes, fuzzy: bool = False) -> int:
        """
        Find signature position in data, with optional fuzzy matching
        
        Returns:
            int: Position of signature, or -1 if not found
        """
        if not fuzzy:
            # Exact match
            pos = data.find(signature)
            return pos
        
        # Fuzzy match: try to find signature with small errors
        # Scan first 500 bytes
        scan_range = min(500, len(data) - len(signature))
        for start_pos in range(scan_range):
            if start_pos + len(signature) > len(data):
                break
            if self._fuzzy_signature_match(data[start_pos:start_pos + len(signature)], signature, max_errors=3):
                return start_pos
        
        # If still not found, try with even more tolerance (up to 4 bit errors)
        for start_pos in range(min(200, len(data) - len(signature))):
            if start_pos + len(signature) > len(data):
                break
            # Count matching bytes (allowing 1-2 byte differences)
            matches = sum(1 for i in range(len(signature)) 
                          if i + start_pos < len(data) and 
                          data[start_pos + i] == signature[i])
            if matches >= len(signature) - 1:  # Allow 1 byte difference
                return start_pos
        
        return -1
    
    def _extract_lsb(self, img: Image.Image) -> bytes:
        """Extract data using LSB method"""
        # Ensure we're working with RGB image
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
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
    
    def embed_archive(self, file_paths: List[str], cover_image: Optional[str] = None,
                     output_image: str = None, password: Optional[str] = None,
                     mode: str = 'lsb', compress: bool = True,
                     quality: int = 95, strip_metadata: bool = True,
                     enable_robustness: Optional[bool] = None,
                     enable_anti_steganalysis: Optional[bool] = None) -> bool:
        """
        Embed multiple files/folders as an archive into an image
        
        Args:
            file_paths: List of file or directory paths to embed
            cover_image: Optional cover image
            output_image: Output stego image path
            password: Optional password for encryption
            mode: 'pixel' or 'lsb'
            compress: Whether to compress archive
            quality: Image quality (1-100)
            strip_metadata: Strip EXIF and other metadata
            enable_robustness: Override default robustness setting
            enable_anti_steganalysis: Override default anti-steganalysis setting
        
        Returns:
            bool: True if successful
        """
        try:
            # Create archive from files
            archive_data = self.archive.create_archive(file_paths)
            
            # Save archive to temp file and embed it
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix='.sva') as tmp:
                tmp.write(archive_data)
                tmp_path = tmp.name
            
            try:
                # Use regular embed_file with archive flag
                success = self.embed_file(
                    input_file=tmp_path,
                    cover_image=cover_image,
                    output_image=output_image,
                    password=password,
                    mode=mode,
                    compress=compress,
                    quality=quality,
                    is_archive=True,
                    strip_metadata=strip_metadata,
                    enable_robustness=enable_robustness if enable_robustness is not None else self._enable_robustness,
                    enable_anti_steganalysis=enable_anti_steganalysis if enable_anti_steganalysis is not None else self._enable_anti_steganalysis
                )
            finally:
                # Clean up temp file
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            
            return success
        except Exception as e:
            self._last_error = str(e)
            return False
    
    def extract_archive(self, stego_image: str, output_dir: str = '.',
                       password: Optional[str] = None,
                       enable_robustness: Optional[bool] = None) -> Optional[Dict]:
        """
        Extract archive from stego image
        
        Args:
            stego_image: Path to stego image
            output_dir: Directory to extract archive to
            password: Password if encrypted
            enable_robustness: Override default robustness setting
        
        Returns:
            dict: Archive extraction results, or None if failed
        """
        try:
            # Extract archive file first
            archive_path = self.extract_file(
                stego_image=stego_image,
                output_path=output_dir,
                password=password,
                verify=True
            )
            
            if not archive_path:
                return None
            
            # Read and extract archive
            with open(archive_path, 'rb') as f:
                archive_data = f.read()
            
            # Check metadata to see if robustness was used (from the stego image)
            # The extract_file already handled robustness recovery, so archive_data should be clean
            # But we check metadata to be sure
            try:
                metadata = self.get_metadata(stego_image, password)
                had_ecc = metadata.get('had_ecc', False) if metadata else False
                had_redundancy = metadata.get('had_redundancy', False) if metadata else False
                
                # Apply robustness recovery if metadata indicates it was used
                if had_ecc or had_redundancy:
                    # Create robustness engine if needed
                    if not self.robustness:
                        self.robustness = RobustnessEngine(redundancy_level=2)
                    try:
                        archive_data, errors = self.robustness.recover_from_social_media(
                            archive_data, had_ecc=had_ecc, had_redundancy=had_redundancy
                        )
                        if errors > 0:
                            self._auto_actions.append(f"Recovered {errors} errors using robustness features")
                    except Exception:
                        pass  # If recovery fails, try without it
            except Exception:
                pass  # If metadata check fails, continue without robustness recovery
            
            # Extract archive
            result = self.archive.extract_archive(archive_data, output_dir)
            
            # Clean up archive file
            try:
                os.unlink(archive_path)
            except Exception:
                pass
            
            return result
        except Exception as e:
            self._last_error = str(e)
            return None
    
    def detect_steganography(self, image_path: str) -> Dict:
        """
        Detect if an image contains steganography
        
        Args:
            image_path: Path to image to analyze
        
        Returns:
            dict: Detection results with risk score
        """
        try:
            # Lazily create protection helper if missing for any reason
            if self.steganalysis is None:
                self.steganalysis = SteganalysisProtection()
            img = Image.open(image_path)
            return self.steganalysis.detect_steganography(img)
        except Exception as e:
            return {'error': str(e)}
    
    def get_capacity_info(self, cover_image: Optional[str] = None,
                         image_size: Optional[tuple] = None,
                         mode: str = 'lsb') -> Dict:
        """
        Get capacity information for an image
        
        Returns:
            dict: Capacity information
        """
        return self.capacity.calculate_capacity(cover_image, image_size, mode)
    
    def check_file_fits(self, file_path: str, cover_image: Optional[str] = None,
                       mode: str = 'lsb', compress: bool = False,
                       password: Optional[str] = None) -> Dict:
        """
        Check if a file will fit in an image
        
        Returns:
            dict: Fit analysis
        """
        return self.capacity.check_file_fits(file_path, cover_image, None, mode, compress, password)
    
    def strip_metadata(self, image_path: str, output_path: Optional[str] = None) -> str:
        """
        Strip metadata from an image
        
        Returns:
            str: Path to cleaned image
        """
        return self.metadata.strip_metadata(image_path, output_path)
    
    def get_privacy_report(self, image_path: str) -> Dict:
        """
        Get privacy report for an image
        
        Returns:
            dict: Privacy report
        """
        return self.metadata.create_privacy_report(image_path)

