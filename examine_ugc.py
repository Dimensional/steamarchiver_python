#!/usr/bin/env python3
"""
Examine a specific UGC file to understand its structure
"""

import os
import sys
import lzma
import struct
import argparse
import json
from pathlib import Path
from format_detection import FormatDetector
from gmod_format import GMadParser, GModDetector, GModContentHandler, extract_legacy_filename_from_url

def get_ugc_info_from_records(ugc_path):
    """Get UGC info from download records"""
    records_file = "./ugc/download_records.json"
    if not os.path.exists(records_file):
        return None
    
    try:
        with open(records_file, 'r', encoding='utf-8') as f:
            records = json.load(f)
        
        # Normalize the path for comparison
        ugc_path_normalized = os.path.normpath(ugc_path)
        
        # Search through all app IDs
        for app_id, app_records in records.items():
            for record in app_records:
                record_path = os.path.normpath(record.get('file_path', ''))
                if record_path == ugc_path_normalized:
                    # Add the app_id back to the record for backward compatibility
                    record_with_app_id = record.copy()
                    record_with_app_id['app_id'] = int(app_id) if app_id.isdigit() else app_id
                    return record_with_app_id
    except Exception as e:
        print(f"Warning: Could not read download records: {e}")
    
    return None

def examine_file(filepath, verbose=False, full=False):
    """Examine the structure of a UGC file"""
    print(f"Examining file: {filepath}")
    
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        return
    
    file_size = os.path.getsize(filepath)
    print(f"File size: {file_size:,} bytes")
    
    # Get UGC info from download records
    ugc_info = get_ugc_info_from_records(filepath)
    if ugc_info:
        print(f"Workshop ID: {ugc_info.get('workshop_id', 'unknown')}")
        print(f"Title: {ugc_info.get('title', 'unknown')}")
        print(f"App ID: {ugc_info.get('app_id', 'unknown')}")
        
        # Extract and show legacy filename from URL
        file_url = ugc_info.get('file_url', '')
        if file_url:
            legacy_filename = extract_legacy_filename_from_url(file_url)
            if legacy_filename:
                print(f"Steam legacy filename: {legacy_filename}")
            print(f"Source URL: {file_url}")
    
    # Read first 64 bytes for analysis
    with open(filepath, 'rb') as f:
        header = f.read(64)
    
    if verbose:
        print(f"First 64 bytes (hex): {header.hex()}")
        print(f"First 64 bytes (ascii): {repr(header)}")
    
    # Detect format
    format_type = FormatDetector.detect_format(header)
    print(f"Detected format: {format_type}")
    
    # If LZMA, try to decompress and examine contents
    if format_type == 'lzma':
        print("\nAttempting LZMA decompression...")
        try:
            with open(filepath, 'rb') as f:
                compressed_data = f.read()
            
            decompressed = lzma.decompress(compressed_data)
            print(f"LZMA decompression successful: {len(decompressed):,} bytes")
            
            # Examine decompressed content
            if verbose:
                print(f"Decompressed first 64 bytes (hex): {decompressed[:64].hex()}")
                print(f"Decompressed first 64 bytes (ascii): {repr(decompressed[:64])}")
            
            # Check if it's any GMod format and use unified handler
            inner_format = FormatDetector.detect_format(decompressed[:64])
            print(f"Inner format detected: {inner_format}")
            
            if inner_format in ['gmad', 'gmodemo', 'gsave', 'gdupe', 'gmap']:
                print(f"\nAnalyzing {inner_format.upper()} structure...")
                try:
                    # Pass the URL to the analyze method
                    source_url = ugc_info.get('file_url', '') if ugc_info else None
                    analysis = GModContentHandler.analyze(decompressed, verbose=verbose, full=full, source_url=source_url)
                    
                    if analysis:
                        print(f"GMod content analysis successful!")
                        print(f"  Type: {analysis['type']}")
                        
                        # Show legacy filename if available
                        if 'steam_legacy_filename' in analysis:
                            print(f"  Steam_Legacy_Filename: {analysis['steam_legacy_filename']}")
                        
                        # Show info
                        if 'info' in analysis:
                            print(f"  Info: {analysis['info']}")
                        
                        # Show JSON info for save/dupe files
                        if 'json_size' in analysis:
                            print(f"  Json_Size: {analysis['json_size']}")
                            if 'json' in analysis:
                                print(f"  Json: {analysis['json']}")
                            elif 'json_preview' in analysis:
                                print(f"  Json_Preview: {analysis['json_preview']}")
                        
                        # Show files for addon files
                        if 'files' in analysis:
                            print(f"  Files: {len(analysis['files'])} files")
                            if full:
                                for i, filename in enumerate(analysis['files'][:10]):  # Show first 10
                                    print(f"    {i+1}. {filename}")
                                if len(analysis['files']) > 10:
                                    print(f"    ... and {len(analysis['files']) - 10} more files")
                        
                        # Show verbose info
                        if verbose:
                            for key in ['size', 'first_bytes', 'first_bytes_ascii', 'decompressed_size', 'decompressed_first_bytes', 'decompressed_first_bytes_ascii']:
                                if key in analysis:
                                    print(f"  {key}: {analysis[key]}")
                        
                        # Show error if any
                        if 'error' in analysis:
                            print(f"  Error: {analysis['error']}")
                        
                        # Show raw data if present
                        if 'raw' in analysis:
                            print(f"  Raw: {analysis['raw']}")
                    else:
                        print(f"GMod content analysis failed")
                except Exception as e:
                    print(f"Error analyzing {inner_format.upper()}: {e}")
            else:
                print(f"Inner content is not GMod format, it's: {inner_format}")
                
                # Check for nested LZMA compression patterns
                nested_lzma_found = False
                
                # Common pattern: LZMA starts at position 17 (save files)
                if not nested_lzma_found and len(decompressed) > 20 and decompressed[17:18] == b'\x5d':
                    print("\nDetected possible nested LZMA compression at position 17...")
                    try:
                        nested_data = lzma.decompress(decompressed[17:])
                        print(f"Nested LZMA decompression successful: {len(nested_data):,} bytes")
                        if verbose:
                            print(f"Nested content first 64 bytes (hex): {nested_data[:64].hex()}")
                            print(f"Nested content first 64 bytes (ascii): {repr(nested_data[:64])}")
                        
                        nested_format = FormatDetector.detect_format(nested_data[:64])
                        print(f"Nested format detected: {nested_format}")
                        
                        # Analyze content type
                        if nested_data.startswith(b'{') or nested_data.startswith(b'['):
                            print("Nested content is JSON format")
                        elif nested_data.startswith(b'"') and b'"' in nested_data[1:100]:
                            print("Nested content might be VDF format")
                        
                        nested_lzma_found = True
                    except Exception as e:
                        print(f"Nested LZMA decompression failed: {e}")
                
                # DUP3 pattern: LZMA starts at position 4
                if not nested_lzma_found and decompressed.startswith(b'DUP3') and len(decompressed) > 8 and decompressed[4:7] == b'\x5d\x00\x00':
                    print("\nDetected nested LZMA in dupe file at position 4...")
                    try:
                        nested_data = lzma.decompress(decompressed[4:])
                        print(f"Nested LZMA decompression successful: {len(nested_data):,} bytes")
                        if verbose:
                            print(f"Nested content first 64 bytes (hex): {nested_data[:64].hex()}")
                            print(f"Nested content first 64 bytes (ascii): {repr(nested_data[:64])}")
                        
                        nested_format = FormatDetector.detect_format(nested_data[:64])
                        print(f"Nested format detected: {nested_format}")
                        
                        # Analyze content type
                        if nested_data.startswith(b'{') or nested_data.startswith(b'['):
                            print("Nested content is JSON format")
                        elif nested_data.startswith(b'"') and b'"' in nested_data[1:100]:
                            print("Nested content might be VDF format")
                        
                        nested_lzma_found = True
                    except Exception as e:
                        print(f"Nested LZMA decompression failed: {e}")
                
                if not nested_lzma_found:
                    # Try to identify other known formats
                    if decompressed.startswith(b'GMAD'):
                        print("Content starts with GMAD but wasn't detected as such - possible parsing issue")
                    elif decompressed.startswith(b'PK'):
                        print("Content appears to be ZIP format")
                    elif decompressed.startswith(b'7z'):
                        print("Content appears to be 7-Zip format")
                    else:
                        print("Content format is unknown - showing more details:")
                        if verbose:
                            print(f"  First 16 bytes: {decompressed[:16].hex()}")
                            print(f"  ASCII representation: {repr(decompressed[:32])}")
                        
                        # Look for common strings that might indicate file type
                        content_sample = decompressed[:1024].decode('utf-8', errors='ignore')
                        if 'GMOD' in content_sample:
                            print("  Content contains 'GMOD' - likely Garry's Mod related")
                        if 'SOURCE' in content_sample:
                            print("  Content contains 'SOURCE' - likely Source Engine related")
                
        except Exception as e:
            print(f"LZMA decompression failed: {e}")
    else:
        print(f"File is not LZMA format, it's: {format_type}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Examine a specific UGC file to understand its structure')
    parser.add_argument('filepath', help='Path to the UGC file to examine')
    parser.add_argument('--verbose', action='store_true', 
                        help='Show verbose output including hex dumps and byte information')
    parser.add_argument('--full', action='store_true',
                        help='Show full content including JSON output or complete file lists')
    
    args = parser.parse_args()
    examine_file(args.filepath, verbose=args.verbose, full=args.full)