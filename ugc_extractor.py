#!/usr/bin/env python3
"""
UGC File Extractor for Steam Workshop Items

This script extracts content from UGC files downloaded by depot_archiver.py.
Supports nested compression and multiple archive formats:

Compression formats (will be unwrapped):
- LZMA/XZ
- GZIP
- BZIP2

Archive formats (final extraction target):
- GMAD (Garry's Mod addon)
- ZIP
- 7-Zip (requires py7zr: pip install py7zr)
- RAR (requires rarfile: pip install rarfile)

The extractor will unwrap nested compression layers until it finds an archive
format containing multiple files, then extract all files from that archive.

Examples:
- LZMA → GMAD → [255 files extracted]
- GZIP → ZIP → [files extracted]
- BZIP2 → LZMA → GMAD → [files extracted]
"""

import os
import sys
import argparse
import struct
import lzma
from pathlib import Path
from io import BytesIO
from gmod_format import GMadParser, GModDetector, GModContentType, GModContentHandler
from format_detection import FormatDetector


def extract_ugc_file(filepath, output_dir=None, max_depth=5):
    """Extract a UGC file recursively"""
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return False
    
    # Set output directory
    if output_dir is None:
        output_dir = os.path.splitext(filepath)[0] + "_extracted"
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Read file
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"Processing file: {filepath}")
    print(f"File size: {len(data):,} bytes")
    
    # Process the file recursively
    return process_ugc_data(data, output_dir, depth=0, max_depth=max_depth)


def process_ugc_data(data, output_dir, depth=0, max_depth=5):
    """Process UGC data recursively, handling nested compression and formats"""
    indent = "  " * depth
    print(f"{indent}Processing data at depth {depth} ({len(data):,} bytes)")
    
    if depth >= max_depth:
        print(f"{indent}Max depth reached, saving as raw data")
        return save_raw_data(data, output_dir, "max_depth_reached.bin")
    
    # Detect format
    format_type = FormatDetector.detect_format(data)
    print(f"{indent}Detected format: {format_type}")
    
    # Handle compression formats - decompress and recurse
    if format_type in ['lzma', 'gzip', 'bzip2']:
        decompressed = decompress_data(data, format_type)
        if decompressed:
            print(f"{indent}Decompressed {format_type.upper()}: {len(decompressed):,} bytes")
            return process_ugc_data(decompressed, output_dir, depth + 1, max_depth)
        else:
            print(f"{indent}Decompression failed, saving as raw data")
            return save_raw_data(data, output_dir, f"failed_{format_type}.bin")
    
    # Handle archive formats - extract contents
    elif format_type in ['zip', '7zip', 'rar']:
        return extract_archive(data, format_type, output_dir)
    
    # Handle GMod content types using unified handler
    elif format_type in ['gmad', 'gmodemo', 'gmap', 'gsave', 'gdupe']:
        return extract_gmod_content(data, format_type, output_dir)
    
    # Unknown format - save as raw data
    else:
        print(f"{indent}Unknown format, saving as raw data")
        return save_raw_data(data, output_dir, "unknown_format.bin")


def decompress_data(data, format_type):
    """Decompress data based on format type"""
    try:
        if format_type == 'lzma':
            return lzma.decompress(data)
        elif format_type == 'gzip':
            import gzip
            return gzip.decompress(data)
        elif format_type == 'bzip2':
            import bz2
            return bz2.decompress(data)
        else:
            return None
    except Exception as e:
        print(f"Error decompressing {format_type}: {e}")
        return None


def extract_gmod_content(data, format_type, output_dir):
    """Extract GMod content using the unified handler"""
    try:
        handler = GModContentHandler()
        
        if format_type == 'gmad':
            # For GMAD files, use the extract method to get files
            result = handler.extract(data, output_dir)
            if result:
                print(f"Successfully extracted GMAD content to {output_dir}")
                return True
            else:
                print("Failed to extract GMAD content")
                return False
        else:
            # For other GMod formats, save the content appropriately
            extension_map = {
                'gmodemo': '.dem',
                'gmap': '.bsp',
                'gsave': '.txt',
                'gdupe': '.txt'
            }
            
            # First try to extract nested content (for save/dupe files)
            if format_type in ['gsave', 'gdupe']:
                try:
                    result = handler.extract(data, output_dir)
                    if result:
                        print(f"Successfully extracted {format_type} content to {output_dir}")
                        return True
                except Exception as e:
                    print(f"Failed to extract nested {format_type} content: {e}")
            
            # Fallback to saving as raw file
            filename = f"gmod_content{extension_map.get(format_type, '.bin')}"
            output_file = os.path.join(output_dir, filename)
            
            with open(output_file, 'wb') as f:
                f.write(data)
            
            print(f"Saved {format_type} content to {output_file}")
            return True
    except Exception as e:
        print(f"Error extracting {format_type} content: {e}")
        return False


def save_raw_data(data, output_dir, filename):
    """Save raw data to file"""
    try:
        output_file = os.path.join(output_dir, filename)
        with open(output_file, 'wb') as f:
            f.write(data)
        print(f"Saved raw data to {output_file}")
        return True
    except Exception as e:
        print(f"Error saving raw data: {e}")
        return False


def extract_archive(data, format_type, output_dir):
    """Extract archive based on format type"""
    if format_type == 'zip':
        return extract_zip_archive(data, output_dir)
    elif format_type == '7zip':
        return extract_7zip_archive(data, output_dir)
    elif format_type == 'rar':
        return extract_rar_archive(data, output_dir)
    else:
        return False


def decompress_gzip(data):
    """Decompress GZIP data"""
    try:
        import gzip
        return gzip.decompress(data)
    except Exception as e:
        print(f"Error decompressing GZIP data: {e}")
        return None


def decompress_bzip2(data):
    """Decompress BZIP2 data"""
    try:
        import bz2
        return bz2.decompress(data)
    except Exception as e:
        print(f"Error decompressing BZIP2 data: {e}")
        return None


def extract_first_zip_file(data):
    """Extract the first file from ZIP data (legacy function - use extract_zip_archive instead)"""
    try:
        import zipfile
        from io import BytesIO
        
        with zipfile.ZipFile(BytesIO(data), 'r') as zip_file:
            # Get the first file
            names = zip_file.namelist()
            if names:
                return zip_file.read(names[0])
        return None
    except Exception as e:
        print(f"Error extracting ZIP data: {e}")
        return None


def extract_zip_archive(data, output_dir):
    """Extract ZIP archive"""
    try:
        import zipfile
        from io import BytesIO
        
        print("Processing ZIP format...")
        with zipfile.ZipFile(BytesIO(data), 'r') as zip_file:
            file_list = zip_file.namelist()
            print(f"Found {len(file_list)} files in ZIP archive")
            
            extracted_count = 0
            for filename in file_list:
                try:
                    # Create output path
                    output_path = Path(output_dir) / filename
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Extract file
                    with zip_file.open(filename) as source:
                        with open(output_path, 'wb') as target:
                            target.write(source.read())
                    
                    file_info = zip_file.getinfo(filename)
                    print(f"Extracted: {filename} ({file_info.file_size:,} bytes)")
                    extracted_count += 1
                except Exception as e:
                    print(f"Error extracting {filename}: {e}")
            
            print(f"Successfully extracted {extracted_count} files to {output_dir}")
            return extracted_count > 0
    except Exception as e:
        print(f"Error processing ZIP archive: {e}")
        return False


def extract_7zip_archive(data, output_dir):
    """Extract 7-Zip archive"""
    try:
        import py7zr
        from io import BytesIO
        
        print("Processing 7-Zip format...")
        with py7zr.SevenZipFile(BytesIO(data), mode='r') as archive:
            file_list = archive.getnames()
            print(f"Found {len(file_list)} files in 7-Zip archive")
            
            archive.extractall(path=output_dir)
            print(f"Successfully extracted {len(file_list)} files to {output_dir}")
            return True
    except ImportError:
        print("Warning: py7zr library not installed. Cannot extract 7-Zip archives.")
        print("Install with: pip install py7zr")
        return False
    except Exception as e:
        print(f"Error processing 7-Zip archive: {e}")
        return False


def extract_rar_archive(data, output_dir):
    """Extract RAR archive"""
    try:
        import rarfile
        from io import BytesIO
        
        print("Processing RAR format...")
        with rarfile.RarFile(BytesIO(data)) as rar:
            file_list = rar.namelist()
            print(f"Found {len(file_list)} files in RAR archive")
            
            extracted_count = 0
            for filename in file_list:
                try:
                    # Create output path
                    output_path = Path(output_dir) / filename
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Extract file
                    with rar.open(filename) as source:
                        with open(output_path, 'wb') as target:
                            target.write(source.read())
                    
                    info = rar.getinfo(filename)
                    print(f"Extracted: {filename} ({info.file_size:,} bytes)")
                    extracted_count += 1
                except Exception as e:
                    print(f"Error extracting {filename}: {e}")
            
            print(f"Successfully extracted {extracted_count} files to {output_dir}")
            return extracted_count > 0
    except ImportError:
        print("Warning: rarfile library not installed. Cannot extract RAR archives.")
        print("Install with: pip install rarfile")
        return False
    except Exception as e:
        print(f"Error processing RAR archive: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Extract UGC files downloaded by depot_archiver.py')
    parser.add_argument('input', help='Input UGC file or directory')
    parser.add_argument('-o', '--output', help='Output directory (default: <input>_extracted)')
    parser.add_argument('-r', '--recursive', action='store_true', help='Process all files in directory recursively')
    
    args = parser.parse_args()
    
    input_path = Path(args.input)
    
    if input_path.is_file():
        # Single file
        output_dir = args.output or str(input_path.with_suffix('')) + "_extracted"
        success = extract_ugc_file(str(input_path), output_dir)
        sys.exit(0 if success else 1)
    elif input_path.is_dir():
        # Directory
        if args.recursive:
            files = list(input_path.rglob('*'))
        else:
            files = list(input_path.glob('*'))
        
        success_count = 0
        total_count = 0
        
        for filepath in files:
            if filepath.is_file():
                total_count += 1
                output_dir = args.output or str(filepath.with_suffix('')) + "_extracted"
                if extract_ugc_file(str(filepath), output_dir):
                    success_count += 1
        
        print(f"Processed {total_count} files, {success_count} successful")
        sys.exit(0 if success_count == total_count else 1)
    else:
        print(f"Error: Input path not found: {input_path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
