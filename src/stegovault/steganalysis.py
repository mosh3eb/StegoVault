"""
Anti-steganalysis protection for StegoVault
Implements histogram preservation and adaptive LSB selection
"""

import numpy as np
from typing import Tuple, List, Optional, Dict
from PIL import Image


class SteganalysisProtection:
    """Protects against steganalysis detection"""
    
    def __init__(self):
        pass
    
    def analyze_cover_image(self, img: Image.Image) -> Dict:
        """
        Analyze cover image to understand its statistical properties
        
        Returns:
            dict: Statistical properties of the image
        """
        img_array = np.array(img)
        height, width = img_array.shape[:2]
        
        # Calculate histogram for each channel
        histograms = {}
        for channel in range(3):
            hist, bins = np.histogram(img_array[:, :, channel].flatten(), bins=256, range=(0, 256))
            histograms[channel] = {
                'hist': hist,
                'mean': float(np.mean(img_array[:, :, channel])),
                'std': float(np.std(img_array[:, :, channel])),
                'variance': float(np.var(img_array[:, :, channel]))
            }
        
        # Calculate pixel pair statistics (for LSB pair analysis)
        pair_stats = self._calculate_pair_statistics(img_array)
        
        return {
            'histograms': histograms,
            'pair_stats': pair_stats,
            'size': (width, height),
            'total_pixels': width * height
        }
    
    def _calculate_pair_statistics(self, img_array: np.ndarray) -> Dict:
        """Calculate statistics of pixel pairs for LSB analysis"""
        height, width = img_array.shape[:2]
        
        # Count pairs where LSB differs
        pair_differences = {0: 0, 1: 0, 2: 0, 3: 0}  # 0-3 bit differences
        
        for channel in range(3):
            channel_data = img_array[:, :, channel].flatten()
            for i in range(len(channel_data) - 1):
                diff = abs(int(channel_data[i]) - int(channel_data[i+1]))
                pair_differences[min(diff, 3)] += 1
        
        return pair_differences
    
    def select_safe_pixels(self, img_array: np.ndarray, num_bits_needed: int, 
                          analysis: Dict) -> List[Tuple[int, int, int]]:
        """
        Select pixels that are safe to modify without creating detectable patterns
        
        Args:
            img_array: Image array
            num_bits_needed: Number of bits needed
            analysis: Image analysis results
        
        Returns:
            list: List of (y, x, channel) tuples for safe pixel modifications
        """
        height, width = img_array.shape[:2]
        safe_pixels = []
        
        # Strategy: Prefer pixels that are already "noisy" (high variance areas)
        # Avoid smooth areas where LSB changes are more detectable
        
        # Calculate local variance for each pixel
        variance_map = np.zeros((height, width, 3))
        window_size = 3
        
        for y in range(height):
            for x in range(width):
                for c in range(3):
                    y_start = max(0, y - window_size // 2)
                    y_end = min(height, y + window_size // 2 + 1)
                    x_start = max(0, x - window_size // 2)
                    x_end = min(width, x + window_size // 2 + 1)
                    
                    local_region = img_array[y_start:y_end, x_start:x_end, c]
                    variance_map[y, x, c] = np.var(local_region)
        
        # Select pixels with higher variance (noisier areas are safer)
        # Flatten and sort by variance
        pixel_candidates = []
        for y in range(height):
            for x in range(width):
                for c in range(3):
                    variance = variance_map[y, x, c]
                    pixel_value = img_array[y, x, c]
                    pixel_candidates.append((variance, y, x, c, pixel_value))
        
        # Sort by variance (descending) - prefer noisy pixels
        pixel_candidates.sort(key=lambda x: x[0], reverse=True)
        
        # Select pixels, but avoid creating patterns
        selected = []
        used_positions = set()
        
        for variance, y, x, c, pixel_value in pixel_candidates:
            if len(selected) >= num_bits_needed:
                break
            
            # Avoid selecting adjacent pixels to prevent patterns
            neighbors = [
                (y-1, x, c), (y+1, x, c),
                (y, x-1, c), (y, x+1, c),
                (y-1, x-1, c), (y-1, x+1, c),
                (y+1, x-1, c), (y+1, x+1, c)
            ]
            
            # Check if any neighbor is already selected
            has_neighbor = any(pos in used_positions for pos in neighbors)
            
            if not has_neighbor:
                selected.append((y, x, c))
                used_positions.add((y, x, c))
        
        # If we don't have enough, fill with remaining candidates
        if len(selected) < num_bits_needed:
            for variance, y, x, c, pixel_value in pixel_candidates:
                if len(selected) >= num_bits_needed:
                    break
                if (y, x, c) not in used_positions:
                    selected.append((y, x, c))
                    used_positions.add((y, x, c))
        
        return selected[:num_bits_needed]
    
    def preserve_histogram(self, original_img: Image.Image, 
                          modified_img: Image.Image) -> Image.Image:
        """
        Adjust modified image to preserve original histogram statistics
        
        Args:
            original_img: Original cover image
            modified_img: Modified stego image
        
        Returns:
            Image: Adjusted image with preserved histogram
        """
        original_array = np.array(original_img)
        modified_array = np.array(modified_img)
        
        adjusted_array = modified_array.copy()
        
        # For each channel, adjust histogram to match original
        for channel in range(3):
            orig_channel = original_array[:, :, channel]
            mod_channel = modified_array[:, :, channel]
            
            # Calculate histograms
            orig_hist, orig_bins = np.histogram(orig_channel.flatten(), bins=256, range=(0, 256))
            mod_hist, mod_bins = np.histogram(mod_channel.flatten(), bins=256, range=(0, 256))
            
            # Calculate cumulative distribution functions
            orig_cdf = np.cumsum(orig_hist).astype(np.float64)
            orig_cdf = orig_cdf / orig_cdf[-1]  # Normalize
            
            mod_cdf = np.cumsum(mod_hist).astype(np.float64)
            mod_cdf = mod_cdf / mod_cdf[-1]  # Normalize
            
            # Histogram matching: map modified values to match original distribution
            # This is a simplified version - full implementation would use more sophisticated matching
            mapping = np.zeros(256, dtype=np.uint8)
            for i in range(256):
                # Find closest CDF value in original
                target_cdf = mod_cdf[i]
                closest_idx = np.argmin(np.abs(orig_cdf - target_cdf))
                mapping[i] = closest_idx
            
            # Apply mapping
            adjusted_channel = mapping[mod_channel]
            adjusted_array[:, :, channel] = adjusted_channel
        
        return Image.fromarray(adjusted_array)
    
    def detect_steganography(self, img: Image.Image) -> Dict:
        """
        Detect if an image might contain steganography
        
        Returns:
            dict: Detection results with risk score
        """
        img_array = np.array(img)
        height, width = img_array.shape[:2]
        
        # LSB analysis: Check for unnatural LSB patterns
        lsb_patterns = self._analyze_lsb_patterns(img_array)
        
        # Histogram analysis: Check for histogram anomalies
        histogram_anomalies = self._analyze_histogram(img_array)
        
        # RS analysis: Regular-Singular groups analysis
        rs_analysis = self._rs_analysis(img_array)
        
        # Calculate risk score (0-100)
        risk_score = 0
        
        # LSB pattern risk
        if lsb_patterns['suspicious_patterns'] > 0.1:  # More than 10% suspicious
            risk_score += 30
        
        # Histogram risk
        if histogram_anomalies['anomaly_score'] > 0.15:
            risk_score += 25
        
        # RS analysis risk
        if rs_analysis['detected']:
            risk_score += 45
        
        risk_score = min(100, risk_score)
        
        # Determine risk level
        if risk_score < 30:
            risk_level = "Low"
        elif risk_score < 60:
            risk_level = "Medium"
        else:
            risk_level = "High"
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'lsb_analysis': lsb_patterns,
            'histogram_analysis': histogram_anomalies,
            'rs_analysis': rs_analysis,
            'detected': risk_score >= 50
        }
    
    def _analyze_lsb_patterns(self, img_array: np.ndarray) -> Dict:
        """Analyze LSB patterns for steganography detection"""
        height, width = img_array.shape[:2]
        
        # Count LSB transitions
        lsb_transitions = 0
        total_pairs = 0
        
        for channel in range(3):
            channel_data = img_array[:, :, channel].flatten()
            for i in range(len(channel_data) - 1):
                lsb1 = channel_data[i] & 1
                lsb2 = channel_data[i+1] & 1
                if lsb1 != lsb2:
                    lsb_transitions += 1
                total_pairs += 1
        
        transition_rate = lsb_transitions / total_pairs if total_pairs > 0 else 0
        
        # Natural images have ~50% transition rate
        # Stego images often have different rates
        suspicious_patterns = abs(transition_rate - 0.5)
        
        return {
            'transition_rate': transition_rate,
            'suspicious_patterns': suspicious_patterns
        }
    
    def _analyze_histogram(self, img_array: np.ndarray) -> Dict:
        """Analyze histogram for anomalies"""
        anomalies = 0
        
        for channel in range(3):
            hist, _ = np.histogram(img_array[:, :, channel].flatten(), bins=256, range=(0, 256))
            
            # Check for unnatural spikes or gaps
            # Stego images often have histogram artifacts
            hist_variance = np.var(hist)
            hist_mean = np.mean(hist)
            
            # Count outliers
            threshold = hist_mean + 2 * np.sqrt(hist_variance)
            outliers = np.sum(hist > threshold)
            
            if outliers > 10:  # More than 10 outlier bins
                anomalies += 1
        
        anomaly_score = anomalies / 3.0  # Normalize to 0-1
        
        return {
            'anomaly_score': anomaly_score,
            'anomalies_detected': anomalies > 0
        }
    
    def _rs_analysis(self, img_array: np.ndarray) -> Dict:
        """
        Regular-Singular (RS) analysis for LSB steganography detection
        Simplified implementation
        """
        height, width = img_array.shape[:2]
        
        # Sample a subset for RS analysis (full analysis is computationally expensive)
        sample_size = min(10000, height * width)
        sample_indices = np.random.choice(height * width, sample_size, replace=False)
        
        # Analyze LSB flipping effects
        # This is a simplified version - full RS analysis is more complex
        regular_groups = 0
        singular_groups = 0
        
        # In natural images, R and S should be roughly equal
        # Stego images show imbalance
        
        # Simplified: check LSB distribution
        lsb_distribution = {0: 0, 1: 0}
        for idx in sample_indices:
            y = idx // width
            x = idx % width
            for c in range(3):
                lsb = img_array[y, x, c] & 1
                lsb_distribution[lsb] += 1
        
        total_lsbs = lsb_distribution[0] + lsb_distribution[1]
        if total_lsbs > 0:
            imbalance = abs(lsb_distribution[0] - lsb_distribution[1]) / total_lsbs
            detected = imbalance > 0.1  # More than 10% imbalance suggests stego
        else:
            detected = False
        
        return {
            'detected': detected,
            'lsb_distribution': lsb_distribution,
            'imbalance': imbalance if total_lsbs > 0 else 0
        }
