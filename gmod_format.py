"""
GMod Format Handler for Garry's Mod Workshop Content

This module provides comprehensive handling for all Garry's Mod workshop content types:
- GMAD (Garry's Mod Addon) format files
- GMODEMO (Garry's Mod Demo) format files  
- GMAP (Garry's Mod Map) format files
- GSAVE (Garry's Mod Save) format files

Includes parsing, validation, and extraction capabilities for each format.
"""

import struct
import os
import lzma
import re
from typing import Dict, List, Optional, Any, BinaryIO, Union
from pathlib import Path


def extract_legacy_filename_from_url(url: str) -> Optional[str]:
    """Extract the legacy filename from a Steam UGC URL"""
    # Pattern: https://cdn.steamusercontent.com/ugc/{LEGACY_NUMBER}/{HASH}/
    match = re.search(r'/ugc/(\d+)/', url)
    if match:
        legacy_number = match.group(1)
        return f"{legacy_number}_legacy.bin"
    return None


class GModContentType:
    """Enum for GMod content types"""
    ADDON = "gmad"
    DEMO = "gmodemo"
    MAP = "gmap"
    SAVE = "gsave"
    DUPE = "gdupe"
    UNKNOWN = "unknown"


class GModDetector:
    """Detector for all GMod content types"""
    
    @staticmethod
    def detect_gmod_format(data: bytes) -> str:
        """Detect specific GMod content format"""
        if len(data) < 8:
            return GModContentType.UNKNOWN
        
        if data.startswith(b'GMAD'):
            return GModContentType.ADDON
        elif data.startswith(b'GMODEMO'):
            return GModContentType.DEMO
        elif data.startswith(b'VBSP'):  # Source engine map format
            return GModContentType.MAP
        elif data.startswith(b'GMS3') or data.startswith(b'GMSAVE') or data.startswith(b'SAVE'):
            return GModContentType.SAVE
        elif data.startswith(b'DUP3'):  # GMod duplication format
            return GModContentType.DUPE
        elif GModemoParser.is_compressed_gmodemo(data):
            return GModContentType.DEMO
        else:
            return GModContentType.UNKNOWN
    
    @staticmethod
    def is_gmod_content(data: bytes) -> bool:
        """Check if data is any GMod content type"""
        return GModDetector.detect_gmod_format(data) != GModContentType.UNKNOWN


class GMadHeader:
    """GMAD file header structure"""
    
    def __init__(self):
        self.version: int = 0
        self.steam_id: int = 0
        self.timestamp: int = 0
        self.required_content: str = ""
        self.addon_name: str = ""
        self.addon_description: str = ""
        self.addon_author: str = ""
        self.addon_version: int = 0
        self.header_size: int = 0


class GMadFileEntry:
    """GMAD file entry structure"""
    
    def __init__(self):
        self.index: int = 0
        self.file_num: int = 0
        self.filename: str = ""
        self.size: int = 0
        self.crc: int = 0
        self.offset: int = 0


class GMadFile:
    """Complete GMAD file representation"""
    
    def __init__(self):
        self.header: GMadHeader = GMadHeader()
        self.files: List[GMadFileEntry] = []
        self.data: bytes = b''
        self.compressed: bool = False
        self.original_size: int = 0


class GMadParser:
    """GMAD file parser and handler"""
    
    @staticmethod
    def is_gmad_file(data: bytes) -> bool:
        """Check if data represents a GMAD file"""
        return data.startswith(b'GMAD')
    
    @staticmethod
    def is_compressed_gmad(data: bytes) -> bool:
        """Check if data is LZMA compressed GMAD"""
        try:
            # Try LZMA decompression
            decompressed = lzma.decompress(data)
            return decompressed.startswith(b'GMAD')
        except:
            return False
    
    @staticmethod
    def decompress_gmad(data: bytes) -> Optional[bytes]:
        """Decompress LZMA compressed GMAD data"""
        try:
            return lzma.decompress(data)
        except Exception as e:
            print(f"Error decompressing GMAD: {e}")
            return None
    
    @staticmethod
    def parse_header(data: bytes) -> Optional[GMadHeader]:
        """Parse GMAD header from data"""
        if not data.startswith(b'GMAD'):
            return None
        
        if len(data) < 21:
            return None
        
        header = GMadHeader()
        header.version = data[4]
        header.steam_id = struct.unpack('<Q', data[5:13])[0]
        header.timestamp = struct.unpack('<Q', data[13:21])[0]
        
        # Parse null-terminated strings
        offset = 21
        
        # Required content
        header.required_content = GMadParser._read_null_terminated_string(data, offset)
        offset += len(header.required_content.encode('utf-8')) + 1
        
        # Addon name
        header.addon_name = GMadParser._read_null_terminated_string(data, offset)
        offset += len(header.addon_name.encode('utf-8')) + 1
        
        # Addon description
        header.addon_description = GMadParser._read_null_terminated_string(data, offset)
        offset += len(header.addon_description.encode('utf-8')) + 1
        
        # Addon author
        header.addon_author = GMadParser._read_null_terminated_string(data, offset)
        offset += len(header.addon_author.encode('utf-8')) + 1
        
        # Addon version
        if offset + 4 <= len(data):
            header.addon_version = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
        
        header.header_size = offset
        return header
    
    @staticmethod
    def _read_null_terminated_string(data: bytes, offset: int) -> str:
        """Read null-terminated string from data at offset"""
        end_offset = offset
        while end_offset < len(data) and data[end_offset] != 0:
            end_offset += 1
        
        if end_offset < len(data):
            return data[offset:end_offset].decode('utf-8', errors='ignore')
        return ""
    
    @staticmethod
    def parse_file_entries(data: bytes, header_size: int) -> List[GMadFileEntry]:
        """Parse file entries from GMAD data"""
        if len(data) < header_size + 4:
            return []
        
        files = []
        offset = header_size + 4  # Skip mystery bytes
        file_index = 0
        
        while offset < len(data):
            if offset + 4 > len(data):
                break
            
            # Read file entry number
            file_num = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            # End of file entries
            if file_num == 0:
                break
            
            # Read filename
            filename = GMadParser._read_null_terminated_string(data, offset)
            offset += len(filename.encode('utf-8')) + 1
            
            if offset + 12 > len(data):
                break
            
            # Read file size and CRC
            file_size = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            crc = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            # Validate file entry
            if GMadParser._is_valid_file_entry(filename, file_size):
                entry = GMadFileEntry()
                entry.index = file_index
                entry.file_num = file_num
                entry.filename = filename
                entry.size = file_size
                entry.crc = crc
                files.append(entry)
                file_index += 1
        
        return files
    
    @staticmethod
    def _is_valid_file_entry(filename: str, file_size: int) -> bool:
        """Validate file entry"""
        if not filename or filename.startswith('\x00'):
            return False
        if file_size <= 0 or file_size > 1024 * 1024 * 1024:  # Max 1GB
            return False
        return True
    
    @staticmethod
    def parse_file(filepath: str) -> Optional[GMadFile]:
        """Parse a GMAD file from disk"""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
            
            return GMadParser.parse_data(data)
        except Exception as e:
            print(f"Error parsing GMAD file {filepath}: {e}")
            return None
    
    @staticmethod
    def parse_data(data: bytes) -> Optional[GMadFile]:
        """Parse GMAD data"""
        gmad = GMadFile()
        gmad.original_size = len(data)
        
        # Check if compressed
        if GMadParser.is_compressed_gmad(data):
            gmad.compressed = True
            decompressed = GMadParser.decompress_gmad(data)
            if not decompressed:
                return None
            data = decompressed
        
        # Parse header
        header = GMadParser.parse_header(data)
        if not header:
            return None
        
        gmad.header = header
        
        # Parse file entries
        gmad.files = GMadParser.parse_file_entries(data, header.header_size)
        
        # Store data
        gmad.data = data
        
        return gmad
    
    @staticmethod
    def get_file_data_offset(gmad: GMadFile) -> int:
        """Get offset where file data starts"""
        offset = gmad.header.header_size + 4  # Skip mystery bytes
        
        # Skip through file entries
        for file_entry in gmad.files:
            offset += 4  # file_num
            offset += len(file_entry.filename.encode('utf-8')) + 1  # filename + null
            offset += 12  # size + crc
        
        offset += 4  # End marker (file_num = 0)
        return offset
    
    @staticmethod
    def extract_file(gmad: GMadFile, file_entry: GMadFileEntry, output_path: str) -> bool:
        """Extract a single file from GMAD"""
        try:
            # Calculate file data offset
            data_offset = GMadParser.get_file_data_offset(gmad)
            
            # Find file's position in data
            current_offset = data_offset
            for file_info in gmad.files:
                if file_info.index == file_entry.index:
                    break
                current_offset += file_info.size
            
            # Check bounds
            if current_offset + file_entry.size > len(gmad.data):
                print(f"File {file_entry.filename} extends beyond data")
                return False
            
            # Extract file data
            file_data = gmad.data[current_offset:current_offset + file_entry.size]
            
            # Create output directory
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Write file
            with open(output_path, 'wb') as f:
                f.write(file_data)
            
            return True
        except Exception as e:
            print(f"Error extracting file {file_entry.filename}: {e}")
            return False
    
    @staticmethod
    def extract_all(gmad: GMadFile, output_dir: str) -> int:
        """Extract all files from GMAD"""
        extracted_count = 0
        data_offset = GMadParser.get_file_data_offset(gmad)
        current_offset = data_offset
        
        for file_entry in gmad.files:
            output_path = os.path.join(output_dir, file_entry.filename)
            
            if GMadParser.extract_file(gmad, file_entry, output_path):
                extracted_count += 1
            
            current_offset += file_entry.size
        
        return extracted_count
    
    @staticmethod
    def get_info(gmad: GMadFile) -> Dict[str, Any]:
        """Get comprehensive information about GMAD file"""
        total_size = sum(f.size for f in gmad.files)
        
        # File type distribution
        file_types = {}
        for file_entry in gmad.files:
            ext = os.path.splitext(file_entry.filename)[1].lower()
            file_types[ext] = file_types.get(ext, 0) + 1
        
        return {
            'header': {
                'version': gmad.header.version,
                'steam_id': gmad.header.steam_id,
                'timestamp': gmad.header.timestamp,
                'addon_name': gmad.header.addon_name,
                'addon_description': gmad.header.addon_description,
                'addon_author': gmad.header.addon_author,
                'addon_version': gmad.header.addon_version,
                'required_content': gmad.header.required_content
            },
            'files': {
                'count': len(gmad.files),
                'total_size': total_size,
                'file_types': file_types
            },
            'compression': {
                'compressed': gmad.compressed,
                'original_size': gmad.original_size,
                'decompressed_size': len(gmad.data),
                'compression_ratio': gmad.original_size / len(gmad.data) if gmad.compressed else 1.0
            }
        }


def analyze_gmad_file(filepath: str) -> Optional[Dict[str, Any]]:
    """Analyze a GMAD file and return information"""
    gmad = GMadParser.parse_file(filepath)
    if gmad:
        return GMadParser.get_info(gmad)
    return None


def extract_gmad_file(filepath: str, output_dir: str) -> bool:
    """Extract a GMAD file to directory"""
    gmad = GMadParser.parse_file(filepath)
    if gmad:
        extracted_count = GMadParser.extract_all(gmad, output_dir)
        print(f"Extracted {extracted_count} files from {filepath}")
        return extracted_count > 0
    return False


class GModemoHeader:
    """GMODEMO file header structure"""
    
    def __init__(self):
        self.magic: str = ""
        self.version: int = 0
        self.protocol: int = 0
        self.server_name: str = ""
        self.client_name: str = ""
        self.map_name: str = ""
        self.game_directory: str = ""
        self.playback_time: float = 0.0
        self.ticks: int = 0
        self.frames: int = 0
        self.signon_length: int = 0


class GModemoParser:
    """GMODEMO file parser and handler"""
    
    @staticmethod
    def is_gmodemo_file(data: bytes) -> bool:
        """Check if data represents a GMODEMO file"""
        return data.startswith(b'GMODEMO')
    
    @staticmethod
    def is_compressed_gmodemo(data: bytes) -> bool:
        """Check if data is LZMA compressed GMODEMO"""
        try:
            # Try LZMA decompression
            decompressed = lzma.decompress(data)
            return decompressed.startswith(b'GMODEMO')
        except:
            return False
    
    @staticmethod
    def decompress_gmodemo(data: bytes) -> Optional[bytes]:
        """Decompress LZMA compressed GMODEMO data"""
        try:
            return lzma.decompress(data)
        except Exception as e:
            print(f"Error decompressing GMODEMO: {e}")
            return None
    
    @staticmethod
    def parse_header(data: bytes) -> Optional[GModemoHeader]:
        """Parse GMODEMO header from data"""
        if not data.startswith(b'GMODEMO'):
            return None
        
        if len(data) < 1024:  # Need at least 1024 bytes for header
            return None
        
        header = GModemoHeader()
        offset = 0
        
        # Magic signature
        header.magic = data[offset:offset+8].decode('ascii', errors='ignore')
        offset += 8
        
        # Demo file version
        header.version = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        # Network protocol
        header.protocol = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        # Server name (null-terminated string)
        header.server_name = GModemoParser._read_fixed_string(data, offset, 260)
        offset += 260
        
        # Client name (null-terminated string)
        header.client_name = GModemoParser._read_fixed_string(data, offset, 260)
        offset += 260
        
        # Map name (null-terminated string)
        header.map_name = GModemoParser._read_fixed_string(data, offset, 260)
        offset += 260
        
        # Game directory (null-terminated string)
        header.game_directory = GModemoParser._read_fixed_string(data, offset, 260)
        offset += 260
        
        # Playback time (float)
        header.playback_time = struct.unpack('<f', data[offset:offset+4])[0]
        offset += 4
        
        # Ticks (int)
        header.ticks = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        # Frames (int)
        header.frames = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        # Signon length (int)
        header.signon_length = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        return header
    
    @staticmethod
    def _read_fixed_string(data: bytes, offset: int, length: int) -> str:
        """Read fixed-length null-terminated string from data at offset"""
        if offset + length > len(data):
            return ""
        
        # Find null terminator within the fixed length
        end_offset = offset
        while end_offset < offset + length and data[end_offset] != 0:
            end_offset += 1
        
        return data[offset:end_offset].decode('utf-8', errors='ignore')
    
    @staticmethod
    def get_info(header: GModemoHeader) -> Dict[str, Any]:
        """Get comprehensive information about GMODEMO file"""
        return {
            'magic': header.magic,
            'version': header.version,
            'protocol': header.protocol,
            'server_name': header.server_name,
            'client_name': header.client_name,
            'map_name': header.map_name,
            'game_directory': header.game_directory,
            'playback_time': header.playback_time,
            'ticks': header.ticks,
            'frames': header.frames,
            'signon_length': header.signon_length
        }


def analyze_gmodemo_file(filepath: str) -> Optional[Dict[str, Any]]:
    """Analyze a GMODEMO file and return information"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        header = GModemoParser.parse_header(data)
        if header:
            return GModemoParser.get_info(header)
        return None
    except Exception as e:
        print(f"Error analyzing GMODEMO file {filepath}: {e}")
        return None


class GModContentHandler:
    """Unified handler for all GMod content types (analyze/extract)"""
    @staticmethod
    def analyze(data: bytes, verbose: bool = False, full: bool = False, source_url: str = None) -> dict:
        fmt = GModDetector.detect_gmod_format(data)
        result = {'type': fmt}
        
        # Add raw data info for verbose mode
        if verbose:
            result['size'] = len(data)
            result['first_bytes'] = data[:64].hex()
            result['first_bytes_ascii'] = repr(data[:64])
        
        # Add legacy filename information if source URL is provided
        if source_url:
            legacy_filename = extract_legacy_filename_from_url(source_url)
            if legacy_filename:
                result['steam_legacy_filename'] = legacy_filename
        
        if fmt == GModContentType.ADDON:
            gmad = GMadParser.parse_data(data)
            if not gmad:
                result['error'] = 'Failed to parse GMAD'
                return result
            info = GMadParser.get_info(gmad)
            result['info'] = info
            if full:
                result['files'] = [f.filename for f in gmad.files]
        elif fmt == GModContentType.DEMO:
            # Demo: check if compressed and decompress if needed
            original_data = data
            compressed = False
            
            if not data.startswith(b'GMODEMO'):
                # Try to decompress
                decompressed = GModemoParser.decompress_gmodemo(data)
                if decompressed:
                    data = decompressed
                    compressed = True
            
            # Parse header for detailed info
            header = GModemoParser.parse_header(data)
            if header:
                result['info'] = GModemoParser.get_info(header)
                if compressed:
                    result['info']['compressed'] = True
                    result['info']['original_size'] = len(original_data)
                    result['info']['decompressed_size'] = len(data)
                    result['info']['compression_ratio'] = len(original_data) / len(data)
            else:
                result['info'] = {'size': len(data)}
            
            if verbose:
                if compressed:
                    result['compressed_first_bytes'] = original_data[:64].hex()
                    result['compressed_first_bytes_ascii'] = repr(original_data[:64])
                result['decompressed_first_bytes'] = data[:64].hex()
                result['decompressed_first_bytes_ascii'] = repr(data[:64])
        elif fmt in (GModContentType.SAVE, GModContentType.DUPE):
            # Save/Dupe: handle nested LZMA and JSON
            import lzma, json
            # Find nested LZMA
            if fmt == GModContentType.SAVE:
                header_end = data.find(b'\x00', 4)
                if header_end != -1 and header_end + 1 < len(data):
                    potential_lzma = data[header_end + 1:]
                else:
                    potential_lzma = None
            else:  # DUPE
                potential_lzma = data[4:] if len(data) > 4 else None
            
            if potential_lzma and len(potential_lzma) > 4 and potential_lzma.startswith(b'\x5d\x00\x00'):
                try:
                    nested_data = lzma.decompress(potential_lzma)
                    if verbose:
                        result['decompressed_size'] = len(nested_data)
                        result['decompressed_first_bytes'] = nested_data[:64].hex()
                        result['decompressed_first_bytes_ascii'] = repr(nested_data[:64])
                    
                    if nested_data.startswith(b'{') or nested_data.startswith(b'['):
                        result['json_size'] = len(nested_data)
                        if full:
                            result['json'] = nested_data.decode('utf-8', errors='ignore')
                        else:
                            result['json_preview'] = nested_data[:512].decode('utf-8', errors='ignore')
                    else:
                        result['raw'] = nested_data[:128]
                except Exception as e:
                    result['error'] = f'Nested LZMA decompress failed: {e}'
            else:
                result['raw'] = data[:128]
        else:
            result['raw'] = data[:128]
        return result

    @staticmethod
    def extract(data: bytes, output_dir: str, force_extract: bool = False) -> bool:
        fmt = GModDetector.detect_gmod_format(data)
        if fmt == GModContentType.ADDON:
            gmad = GMadParser.parse_data(data)
            if not gmad:
                print('Failed to parse GMAD')
                return False
            count = GMadParser.extract_all(gmad, output_dir)
            print(f"Extracted {count} files to {output_dir}")
            return count > 0
        elif fmt in (GModContentType.SAVE, GModContentType.DUPE):
            import lzma
            # Save/Dupe: extract only the JSON
            if fmt == GModContentType.SAVE:
                header_end = data.find(b'\x00', 4)
                if header_end != -1 and header_end + 1 < len(data):
                    potential_lzma = data[header_end + 1:]
                else:
                    potential_lzma = None
            else:  # DUPE
                potential_lzma = data[4:] if len(data) > 4 else None
            
            if potential_lzma and potential_lzma.startswith(b'\x5d\x00\x00'):
                try:
                    nested_data = lzma.decompress(potential_lzma)
                    if nested_data.startswith(b'{') or nested_data.startswith(b'['):
                        outname = 'gmod_save_data.json' if fmt == GModContentType.SAVE else 'gmod_dupe_data.json'
                        with open(Path(output_dir)/outname, 'wb') as f:
                            f.write(nested_data)
                        print(f"Saved {outname} to {output_dir}")
                        return True
                except Exception as e:
                    print(f"Failed to decompress nested LZMA: {e}")
            print('No valid nested JSON found')
            return False
        elif fmt == GModContentType.DEMO:
            if not force_extract:
                print(f"Demo file detected. Use --force-extract to decompress and extract.")
                print(f"Original compressed format preserved in UGC file.")
                return False
            
            # For compressed demo files, we can save either the original compressed version
            # or the decompressed version. Let's save the decompressed version to match
            # the current extraction behavior, but add the original compressed file too.
            
            original_data = data
            compressed = False
            
            if not data.startswith(b'GMODEMO'):
                # Try to decompress
                decompressed = GModemoParser.decompress_gmodemo(data)
                if decompressed:
                    data = decompressed
                    compressed = True
            
            # Save the decompressed demo file
            outname = 'gmod_content.dem'
            with open(Path(output_dir)/outname, 'wb') as f:
                f.write(data)
            print(f"Saved {outname} to {output_dir}")
            
            # If it was compressed, also save the original compressed file
            if compressed:
                compressed_outname = 'gmod_content_compressed.dem'
                with open(Path(output_dir)/compressed_outname, 'wb') as f:
                    f.write(original_data)
                print(f"Saved {compressed_outname} to {output_dir}")
            
            return True
        else:
            print('Unknown or unsupported GMod content type')
            return False
