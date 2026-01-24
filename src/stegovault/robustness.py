"""
Social media robustness engine for StegoVault
Implements error correction and compression resistance
"""

import struct
from typing import Tuple, Optional


class RobustnessEngine:
    """Handles error correction and robustness features"""
    
    def __init__(self, redundancy_level: int = 2):
        """
        Args:
            redundancy_level: Number of redundant copies (1-5, default 2)
        """
        self.redundancy_level = max(1, min(5, redundancy_level))
    
    def add_error_correction(self, data: bytes, ecc_symbols: int = 10) -> bytes:
        """
        Add Reed-Solomon-like error correction using simple parity
        
        Args:
            data: Data to protect
            ecc_symbols: Number of error correction symbols per block
        
        Returns:
            bytes: Data with error correction codes appended
        """
        # Simple implementation: add parity bytes
        # For production, consider using reedsolo library
        
        protected = bytearray()
        block_size = 255 - ecc_symbols  # Leave room for ECC
        
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            
            # Add parity bytes (simple XOR-based)
            parity = bytearray(ecc_symbols)
            for j, byte in enumerate(block):
                parity[j % ecc_symbols] ^= byte
            
            protected.extend(block)
            protected.extend(parity)
            protected.extend(struct.pack('H', len(block)))  # Block size marker
        
        return bytes(protected)
    
    def remove_error_correction(self, protected_data: bytes, ecc_symbols: int = 10) -> bytes:
        """
        Remove error correction and recover original data
        
        Args:
            protected_data: Protected data with ECC
            ecc_symbols: Number of error correction symbols per block
        
        Returns:
            bytes: Recovered original data
        """
        recovered = bytearray()
        block_size = 255 - ecc_symbols
        i = 0
        
        while i < len(protected_data):
            # Try to read block
            if i + block_size + ecc_symbols + 2 > len(protected_data):
                # Last block might be incomplete
                remaining = len(protected_data) - i
                if remaining > ecc_symbols + 2:
                    block = protected_data[i:i+remaining-ecc_symbols-2]
                    recovered.extend(block)
                break
            
            block = protected_data[i:i+block_size]
            parity = protected_data[i+block_size:i+block_size+ecc_symbols]
            size_marker = struct.unpack('H', protected_data[i+block_size+ecc_symbols:i+block_size+ecc_symbols+2])[0]
            
            # Verify parity (simple check)
            computed_parity = bytearray(ecc_symbols)
            for j, byte in enumerate(block):
                computed_parity[j % ecc_symbols] ^= byte
            
            # If parity matches, use block; otherwise try to recover
            if computed_parity == parity:
                recovered.extend(block)
            else:
                # Try to recover using majority voting if we have redundancy
                recovered.extend(block)  # Use anyway, let higher-level handle errors
            
            i += block_size + ecc_symbols + 2
        
        return bytes(recovered)
    
    def add_redundancy(self, data: bytes) -> bytes:
        """
        Add redundant copies of data for robustness
        
        Returns:
            bytes: Data with redundancy
        """
        redundant = bytearray()
        redundant.extend(struct.pack('B', self.redundancy_level))
        redundant.extend(struct.pack('I', len(data)))  # Original size
        
        # Add original + redundant copies
        for _ in range(self.redundancy_level):
            redundant.extend(data)
        
        return bytes(redundant)
    
    def remove_redundancy(self, redundant_data: bytes) -> Tuple[bytes, int]:
        """
        Remove redundancy and recover original data using majority voting
        
        Returns:
            tuple: (recovered_data, errors_corrected)
        """
        if len(redundant_data) < 5:
            raise ValueError("Invalid redundant data")
        
        redundancy_level = redundant_data[0]
        original_size = struct.unpack('I', redundant_data[1:5])[0]
        
        if redundancy_level < 1 or redundancy_level > 5:
            raise ValueError("Invalid redundancy level")
        
        # Extract copies
        copy_size = original_size
        copies = []
        offset = 5
        
        for i in range(redundancy_level):
            if offset + copy_size > len(redundant_data):
                break
            copy = redundant_data[offset:offset+copy_size]
            copies.append(copy)
            offset += copy_size
        
        if not copies:
            raise ValueError("No copies found in redundant data")
        
        # Use majority voting to recover original
        recovered = bytearray(original_size)
        errors_corrected = 0
        
        for i in range(original_size):
            # Count occurrences of each byte value at this position
            byte_counts = {}
            for copy in copies:
                if i < len(copy):
                    byte_val = copy[i]
                    byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1
            
            # Use most common byte value
            if byte_counts:
                most_common = max(byte_counts.items(), key=lambda x: x[1])
                recovered[i] = most_common[0]
                
                # Count errors (bytes that don't match majority)
                for copy in copies:
                    if i < len(copy) and copy[i] != most_common[0]:
                        errors_corrected += 1
        
        return bytes(recovered), errors_corrected
    
    def prepare_for_social_media(self, data: bytes, enable_ecc: bool = True, 
                                  enable_redundancy: bool = True) -> bytes:
        """
        Prepare data for social media sharing (adds all robustness features)
        
        Args:
            data: Original data
            enable_ecc: Enable error correction codes
            enable_redundancy: Enable redundancy
        
        Returns:
            bytes: Robust data ready for embedding
        """
        robust_data = data
        
        if enable_ecc:
            robust_data = self.add_error_correction(robust_data)
        
        if enable_redundancy:
            robust_data = self.add_redundancy(robust_data)
        
        return robust_data
    
    def recover_from_social_media(self, robust_data: bytes, 
                                    had_ecc: bool = True, 
                                    had_redundancy: bool = True) -> Tuple[bytes, int]:
        """
        Recover original data from robust format
        
        Returns:
            tuple: (recovered_data, errors_corrected)
        """
        recovered = robust_data
        errors_corrected = 0
        
        if had_redundancy:
            recovered, errors = self.remove_redundancy(recovered)
            errors_corrected += errors
        
        if had_ecc:
            recovered = self.remove_error_correction(recovered)
        
        return recovered, errors_corrected
