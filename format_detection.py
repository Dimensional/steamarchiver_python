"""
Format Detection Library for Steam UGC Files

This module provides format detection capabilities for various file formats
commonly found in Steam UGC (User Generated Content) files.
"""

import struct
from typing import Optional, Dict, Any
import os
from pathlib import Path


class FormatDetector:
    """Main format detection class"""
    
    @staticmethod
    def detect_format(data: bytes) -> str:
        """
        Detect file format based on header bytes
        
        Args:
            data: Raw bytes data (at least first 16 bytes)
            
        Returns:
            Format type string ('gzip', 'zip', 'lzma', 'gmad', etc.)
        """
        if len(data) < 4:
            return 'unknown'
        
        # Check for magic bytes
        if data.startswith(b'\x1f\x8b'):
            return 'gzip'
        elif data.startswith(b'PK'):
            return 'zip'
        elif data.startswith(b'\x5d\x00\x00') or data.startswith(b'\xfd7zXZ'):
            return 'lzma'
        elif data.startswith(b'BZh'):
            return 'bzip2'
        elif data.startswith(b'GMAD'):
            return 'gmad'
        elif data.startswith(b'GMODEMO'):
            return 'gmodemo'
        elif data.startswith(b'VBSP'):
            return 'gmap'
        elif data.startswith(b'GMS3') or data.startswith(b'GMSAVE') or data.startswith(b'SAVE'):
            return 'gsave'
        elif data.startswith(b'DUP3'):
            return 'gdupe'
        elif data.startswith(b'"') and b'"' in data[1:100]:  # Basic VDF detection
            return 'vdf'
        elif data.startswith(b'7z\xbc\xaf\x27\x1c'):
            return '7zip'
        elif data.startswith(b'Rar!'):
            return 'rar'
        elif data.startswith(b'\x89PNG'):
            return 'png'
        elif data.startswith(b'\xff\xd8\xff'):
            return 'jpeg'
        elif data.startswith(b'GIF8'):
            return 'gif'
        elif data.startswith(b'RIFF') and data[8:12] == b'WAVE':
            return 'wav'
        elif data.startswith(b'OggS'):
            return 'ogg'
        elif data.startswith(b'ID3') or data.startswith(b'\xff\xfb'):
            return 'mp3'
        elif data.startswith(b'\x00\x00\x00\x18ftypmp4') or data.startswith(b'\x00\x00\x00\x20ftypmp4'):
            return 'mp4'
        else:
            return 'unknown'
    
    @staticmethod
    def is_compressed(format_type: str) -> bool:
        """Check if a format is compressed"""
        compressed_formats = {'gzip', 'zip', 'lzma', 'bzip2', '7zip', 'rar'}
        return format_type in compressed_formats
    
    @staticmethod
    def is_archive(format_type: str) -> bool:
        """Check if a format is an archive (contains multiple files)"""
        archive_formats = {'zip', '7zip', 'rar', 'tar', 'gmad'}
        return format_type in archive_formats
    
    @staticmethod
    def get_format_info(format_type: str) -> Dict[str, Any]:
        """Get detailed information about a format"""
        format_info = {
            'gzip': {
                'name': 'GNU Zip',
                'compressed': True,
                'archive': False,
                'suggested_extension': '.gz',
                'mime_type': 'application/gzip',
                'description': 'GNU Zip compressed data'
            },
            'zip': {
                'name': 'ZIP Archive',
                'compressed': True,
                'archive': True,
                'suggested_extension': '.zip',
                'mime_type': 'application/zip',
                'description': 'ZIP archive containing multiple files'
            },
            'lzma': {
                'name': 'LZMA Compressed',
                'compressed': True,
                'archive': False,
                'suggested_extension': '.xz',
                'mime_type': 'application/x-xz',
                'description': 'LZMA compressed data'
            },
            'bzip2': {
                'name': 'BZip2 Compressed',
                'compressed': True,
                'archive': False,
                'suggested_extension': '.bz2',
                'mime_type': 'application/x-bzip2',
                'description': 'BZip2 compressed data'
            },
            'gmad': {
                'name': 'Garrys Mod Addon',
                'compressed': False,
                'archive': True,
                'suggested_extension': '.gma',
                'mime_type': 'application/x-gmad',
                'description': 'Garry\'s Mod addon archive'
            },
            'gmodemo': {
                'name': 'Garrys Mod Demo',
                'compressed': False,
                'archive': False,
                'suggested_extension': '.dem',
                'mime_type': 'application/x-gmodemo',
                'description': 'Garry\'s Mod demo recording file'
            },
            'gmap': {
                'name': 'Garrys Mod Map',
                'compressed': False,
                'archive': False,
                'suggested_extension': '.bsp',
                'mime_type': 'application/x-gmap',
                'description': 'Garry\'s Mod map file (Source Engine BSP)'
            },
            'gsave': {
                'name': 'Garrys Mod Save',
                'compressed': False,
                'archive': False,
                'suggested_extension': '.txt',
                'mime_type': 'application/x-gsave',
                'description': 'Garry\'s Mod save file'
            },
            'gdupe': {
                'name': 'Garrys Mod Dupe',
                'compressed': False,
                'archive': False,
                'suggested_extension': '.txt',
                'mime_type': 'application/x-gdupe',
                'description': 'Garry\'s Mod duplication file'
            },
            'vdf': {
                'name': 'Valve Data Format',
                'compressed': False,
                'archive': False,
                'suggested_extension': '.vdf',
                'mime_type': 'application/x-vdf',
                'description': 'Valve Data Format file'
            },
            '7zip': {
                'name': '7-Zip Archive',
                'compressed': True,
                'archive': True,
                'suggested_extension': '.7z',
                'mime_type': 'application/x-7z-compressed',
                'description': '7-Zip compressed archive'
            },
            'rar': {
                'name': 'RAR Archive',
                'compressed': True,
                'archive': True,
                'suggested_extension': '.rar',
                'mime_type': 'application/x-rar-compressed',
                'description': 'RAR compressed archive'
            },
            'png': {
                'name': 'PNG Image',
                'compressed': False,
                'archive': False,
                'suggested_extension': '.png',
                'mime_type': 'image/png',
                'description': 'Portable Network Graphics image'
            },
            'jpeg': {
                'name': 'JPEG Image',
                'compressed': False,
                'archive': False,
                'suggested_extension': '.jpg',
                'mime_type': 'image/jpeg',
                'description': 'JPEG compressed image'
            },
            'gif': {
                'name': 'GIF Image',
                'compressed': False,
                'archive': False,
                'suggested_extension': '.gif',
                'mime_type': 'image/gif',
                'description': 'Graphics Interchange Format image'
            },
            'wav': {
                'name': 'WAV Audio',
                'compressed': False,
                'archive': False,
                'suggested_extension': '.wav',
                'mime_type': 'audio/wav',
                'description': 'Waveform Audio File Format'
            },
            'ogg': {
                'name': 'OGG Audio',
                'compressed': True,
                'archive': False,
                'suggested_extension': '.ogg',
                'mime_type': 'audio/ogg',
                'description': 'Ogg Vorbis compressed audio'
            },
            'mp3': {
                'name': 'MP3 Audio',
                'compressed': True,
                'archive': False,
                'suggested_extension': '.mp3',
                'mime_type': 'audio/mpeg',
                'description': 'MPEG Layer 3 compressed audio'
            },
            'mp4': {
                'name': 'MP4 Video',
                'compressed': True,
                'archive': False,
                'suggested_extension': '.mp4',
                'mime_type': 'video/mp4',
                'description': 'MPEG-4 video container'
            }
        }
        
        return format_info.get(format_type, {
            'name': 'Unknown Format',
            'compressed': False,
            'archive': False,
            'suggested_extension': '',
            'mime_type': 'application/octet-stream',
            'description': 'Unknown or unsupported file format'
        })


class CompressionDetector:
    """Specialized compression detection"""
    
    @staticmethod
    def detect_compression(data: bytes) -> Optional[str]:
        """
        Detect compression type from data
        
        Args:
            data: Raw bytes data
            
        Returns:
            Compression type or None if not compressed
        """
        if len(data) < 4:
            return None
        
        # GZIP
        if data.startswith(b'\x1f\x8b'):
            return 'gzip'
        
        # LZMA/XZ
        if data.startswith(b'\xfd7zXZ'):
            return 'xz'
        elif data.startswith(b'\x5d\x00\x00'):
            return 'lzma'
        
        # BZip2
        if data.startswith(b'BZh'):
            return 'bzip2'
        
        # LZ4
        if data.startswith(b'\x04"M\x18'):
            return 'lz4'
        
        # Zstandard
        if data.startswith(b'\x28\xb5\x2f\xfd'):
            return 'zstd'
        
        return None
    
    @staticmethod
    def get_compression_info(compression_type: str) -> Dict[str, Any]:
        """Get general characteristics about compression algorithms"""
        compression_info = {
            'gzip': {
                'name': 'GNU Zip',
                'typical_ratio': 'good',
                'typical_speed': 'fast',
                'suggested_extension': '.gz',
                'description': 'Popular general-purpose compression, good balance of speed and size'
            },
            'lzma': {
                'name': 'LZMA',
                'typical_ratio': 'excellent',
                'typical_speed': 'slow',
                'suggested_extension': '.lzma',
                'description': 'High compression ratio, slower processing speed'
            },
            'xz': {
                'name': 'XZ',
                'typical_ratio': 'excellent',
                'typical_speed': 'slow',
                'suggested_extension': '.xz',
                'description': 'LZMA2-based compression with excellent ratio'
            },
            'bzip2': {
                'name': 'BZip2',
                'typical_ratio': 'very good',
                'typical_speed': 'medium',
                'suggested_extension': '.bz2',
                'description': 'Good compression ratio, moderate processing speed'
            },
            'lz4': {
                'name': 'LZ4',
                'typical_ratio': 'fair',
                'typical_speed': 'very fast',
                'suggested_extension': '.lz4',
                'description': 'Extremely fast compression/decompression, lower ratio'
            },
            'zstd': {
                'name': 'Zstandard',
                'typical_ratio': 'very good',
                'typical_speed': 'fast',
                'suggested_extension': '.zst',
                'description': 'Modern compression with good balance of speed and ratio'
            }
        }
        
        return compression_info.get(compression_type, {
            'name': 'Unknown Compression',
            'typical_ratio': 'unknown',
            'typical_speed': 'unknown',
            'suggested_extension': '',
            'description': 'Unknown compression algorithm'
        })


def detect_file_format(filepath: str) -> str:
    """
    Convenience function to detect format from file path
    
    Args:
        filepath: Path to file
        
    Returns:
        Format type string
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read(16)
        return FormatDetector.detect_format(data)
    except Exception:
        return 'unknown'


def analyze_file(filepath: str) -> Dict[str, Any]:
    """
    Analyze a file and return format information (header-based detection only)
    
    Args:
        filepath: Path to file
        
    Returns:
        Dictionary with format analysis
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read(16)
        
        format_type = FormatDetector.detect_format(data)
        format_info = FormatDetector.get_format_info(format_type)
        
        compression_type = CompressionDetector.detect_compression(data)
        compression_info = None
        if compression_type:
            compression_info = CompressionDetector.get_compression_info(compression_type)
        
        return {
            'format': format_type,
            'format_info': format_info,
            'compression': compression_type,
            'compression_info': compression_info,
            'is_compressed': FormatDetector.is_compressed(format_type),
            'is_archive': FormatDetector.is_archive(format_type),
            'suggested_extension': format_info.get('suggested_extension', ''),
            'description': format_info.get('description', 'Unknown format')
        }
    except Exception as e:
        return {
            'format': 'unknown',
            'error': str(e)
        }


def get_file_metrics(filepath: str) -> Dict[str, Any]:
    """
    Get actual file metrics (size, etc.) for a file
    
    Args:
        filepath: Path to file
        
    Returns:
        Dictionary with file metrics
    """
    try:
        file_path = Path(filepath)
        if not file_path.exists():
            return {'error': 'File not found'}
        
        stat = file_path.stat()
        
        return {
            'size_bytes': stat.st_size,
            'size_human': _format_size(stat.st_size),
            'modified_time': stat.st_mtime,
            'created_time': stat.st_ctime,
            'is_file': file_path.is_file(),
            'is_dir': file_path.is_dir(),
            'permissions': oct(stat.st_mode)[-3:]
        }
    except Exception as e:
        return {'error': str(e)}


def _format_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"


def analyze_file_comprehensive(filepath: str) -> Dict[str, Any]:
    """
    Comprehensive file analysis combining format detection and file metrics
    
    Args:
        filepath: Path to file
        
    Returns:
        Dictionary with complete file analysis
    """
    # Get format analysis
    format_analysis = analyze_file(filepath)
    
    # Get file metrics
    file_metrics = get_file_metrics(filepath)
    
    # Combine results
    result = {
        'filepath': filepath,
        'format_analysis': format_analysis,
        'file_metrics': file_metrics
    }
    
    # Add convenience fields
    if 'format' in format_analysis:
        result['detected_format'] = format_analysis['format']
    
    if 'size_bytes' in file_metrics:
        result['file_size'] = file_metrics['size_bytes']
        result['file_size_human'] = file_metrics['size_human']
    
    return result
