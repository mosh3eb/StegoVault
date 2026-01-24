"""
Metadata stripping and privacy features for StegoVault
Removes EXIF data and other privacy leaks
"""

import os
from typing import Dict, Optional
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from datetime import datetime
import random


class MetadataManager:
    """Manages metadata stripping and privacy features"""
    
    def __init__(self):
        pass
    
    def analyze_metadata(self, image_path: str) -> Dict:
        """
        Analyze all metadata in an image
        
        Returns:
            dict: All metadata found in the image
        """
        metadata_info = {
            'exif': {},
            'exif_gps': {},
            'other': {},
            'has_exif': False,
            'has_gps': False,
            'file_size': os.path.getsize(image_path),
            'file_mtime': os.path.getmtime(image_path),
            'file_ctime': os.path.getctime(image_path)
        }
        
        try:
            img = Image.open(image_path)
            
            # Get EXIF data
            exif_data = img.getexif()
            if exif_data:
                metadata_info['has_exif'] = True
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    metadata_info['exif'][tag] = str(value)
                    
                    # Check for GPS data
                    if tag_id == 34853:  # GPS IFD
                        metadata_info['has_gps'] = True
                        if isinstance(value, dict):
                            for gps_tag_id, gps_value in value.items():
                                gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                                metadata_info['exif_gps'][gps_tag] = str(gps_value)
            
            # Get other metadata
            if hasattr(img, 'info'):
                for key, value in img.info.items():
                    if key not in ['exif']:
                        metadata_info['other'][key] = str(value)
        
        except Exception as e:
            metadata_info['error'] = str(e)
        
        return metadata_info
    
    def strip_metadata(self, image_path: str, output_path: Optional[str] = None,
                      strip_all: bool = True) -> str:
        """
        Strip all metadata from an image
        
        Args:
            image_path: Input image path
            output_path: Output path (if None, overwrites input)
            strip_all: If True, removes all metadata including non-EXIF
        
        Returns:
            str: Path to cleaned image
        """
        if output_path is None:
            output_path = image_path
        
        # Load image
        img = Image.open(image_path)
        
        # Convert to RGB if necessary (removes some metadata)
        if img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Create new image without metadata
        # Save to memory first, then reload to strip metadata
        from io import BytesIO
        buffer = BytesIO()
        img.save(buffer, format='PNG')  # PNG doesn't preserve EXIF
        buffer.seek(0)
        clean_img = Image.open(buffer)
        
        # Save cleaned image
        clean_img.save(output_path, format='PNG')
        
        # Also randomize file timestamps if requested
        if strip_all:
            self._randomize_timestamps(output_path)
        
        return output_path
    
    def _randomize_timestamps(self, file_path: str):
        """Randomize file timestamps for privacy"""
        try:
            # Randomize to a date between 2020 and now
            start_date = datetime(2020, 1, 1).timestamp()
            end_date = datetime.now().timestamp()
            random_time = random.uniform(start_date, end_date)
            
            os.utime(file_path, (random_time, random_time))
        except Exception:
            pass  # Ignore errors on timestamp modification
    
    def create_privacy_report(self, image_path: str) -> Dict:
        """
        Create a privacy report showing what metadata exists
        
        Returns:
            dict: Privacy report with recommendations
        """
        metadata = self.analyze_metadata(image_path)
        
        privacy_risks = []
        
        if metadata['has_gps']:
            privacy_risks.append({
                'risk': 'High',
                'type': 'GPS Location',
                'description': 'Image contains GPS coordinates that reveal location',
                'recommendation': 'Remove GPS data immediately'
            })
        
        if metadata['has_exif']:
            exif_risks = []
            risky_tags = ['DateTime', 'DateTimeOriginal', 'Make', 'Model', 'Software', 'Artist']
            
            for tag in risky_tags:
                if tag in metadata['exif']:
                    exif_risks.append(tag)
            
            if exif_risks:
                privacy_risks.append({
                    'risk': 'Medium',
                    'type': 'EXIF Data',
                    'description': f'Image contains EXIF tags: {", ".join(exif_risks)}',
                    'recommendation': 'Remove EXIF data to protect privacy'
                })
        
        if metadata.get('other'):
            privacy_risks.append({
                'risk': 'Low',
                'type': 'Other Metadata',
                'description': f'Image contains {len(metadata["other"])} other metadata fields',
                'recommendation': 'Review and remove if needed'
            })
        
        return {
            'metadata': metadata,
            'privacy_risks': privacy_risks,
            'risk_count': len(privacy_risks),
            'recommendation': 'Strip all metadata' if privacy_risks else 'Image is clean'
        }
