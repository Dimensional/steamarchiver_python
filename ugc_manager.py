#!/usr/bin/env python3
"""
UGC Download Records Manager

This script provides utilities to view and manage UGC download records
created by depot_archiver.py.
"""

import json
import os
import argparse
from datetime import datetime
from pathlib import Path


def load_records():
    """Load UGC download records"""
    records_file = "./ugc/download_records.json"
    if not os.path.exists(records_file):
        return []
    
    try:
        with open(records_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"Error loading records: {e}")
        return []


def format_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes is None:
        return "Unknown"
    
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"


def list_records(records, app_id=None, status=None):
    """List UGC download records"""
    if not records:
        print("No UGC download records found.")
        return
    
    # Filter records
    filtered_records = records
    if app_id:
        filtered_records = [r for r in filtered_records if r.get('app_id') == app_id]
    if status:
        filtered_records = [r for r in filtered_records if r.get('status') == status]
    
    if not filtered_records:
        print("No records match the specified criteria.")
        return
    
    # Sort by timestamp
    filtered_records.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    print(f"Found {len(filtered_records)} UGC record(s):")
    print("-" * 100)
    
    for record in filtered_records:
        workshop_id = record.get('workshop_id', 'Unknown')
        app_id = record.get('app_id', 'Unknown')
        title = record.get('title', 'Unknown')[:50]  # Truncate long titles
        status = record.get('status', 'Unknown')
        file_format = record.get('file_format', 'Unknown')
        file_size = format_size(record.get('file_size'))
        timestamp = record.get('timestamp', 'Unknown')
        
        # Parse timestamp for better display
        try:
            dt = datetime.fromisoformat(timestamp)
            timestamp_str = dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            timestamp_str = timestamp
        
        print(f"Workshop ID: {workshop_id}")
        print(f"App ID: {app_id}")
        print(f"Title: {title}")
        print(f"Status: {status}")
        print(f"Format: {file_format}")
        print(f"Size: {file_size}")
        print(f"Downloaded: {timestamp_str}")
        print(f"Path: {record.get('file_path', 'Unknown')}")
        print(f"URL: {record.get('file_url', 'Unknown')}")
        print("-" * 100)


def show_summary(records):
    """Show summary statistics of UGC downloads"""
    if not records:
        print("No UGC download records found.")
        return
    
    total_records = len(records)
    downloaded_count = len([r for r in records if r.get('status') == 'downloaded'])
    exists_count = len([r for r in records if r.get('status') == 'exists'])
    
    # Count by app ID
    app_counts = {}
    for record in records:
        app_id = record.get('app_id', 'Unknown')
        app_counts[app_id] = app_counts.get(app_id, 0) + 1
    
    # Count by format
    format_counts = {}
    for record in records:
        file_format = record.get('file_format', 'Unknown')
        format_counts[file_format] = format_counts.get(file_format, 0) + 1
    
    # Calculate total size
    total_size = 0
    for record in records:
        if record.get('file_size'):
            total_size += record.get('file_size')
    
    print("UGC Download Summary:")
    print("=" * 50)
    print(f"Total Records: {total_records}")
    print(f"Downloaded: {downloaded_count}")
    print(f"Already Existed: {exists_count}")
    print(f"Total Size: {format_size(total_size)}")
    print()
    
    print("Records by App ID:")
    for app_id, count in sorted(app_counts.items()):
        print(f"  {app_id}: {count}")
    print()
    
    print("Records by Format:")
    for file_format, count in sorted(format_counts.items()):
        print(f"  {file_format}: {count}")


def verify_files(records):
    """Verify that downloaded files still exist"""
    if not records:
        print("No UGC download records found.")
        return
    
    missing_files = []
    existing_files = []
    
    for record in records:
        file_path = record.get('file_path')
        if file_path and os.path.exists(file_path):
            existing_files.append(record)
        else:
            missing_files.append(record)
    
    print(f"File Verification Results:")
    print(f"Existing files: {len(existing_files)}")
    print(f"Missing files: {len(missing_files)}")
    
    if missing_files:
        print("\nMissing files:")
        for record in missing_files:
            print(f"  Workshop ID {record.get('workshop_id')}: {record.get('file_path')}")


def cleanup_records(records):
    """Clean up records for missing files"""
    if not records:
        print("No UGC download records found.")
        return
    
    existing_records = []
    removed_count = 0
    
    for record in records:
        file_path = record.get('file_path')
        if file_path and os.path.exists(file_path):
            existing_records.append(record)
        else:
            removed_count += 1
    
    if removed_count > 0:
        # Save cleaned records
        records_file = "./ugc/download_records.json"
        try:
            with open(records_file, 'w', encoding='utf-8') as f:
                json.dump(existing_records, f, indent=2, ensure_ascii=False)
            print(f"Cleaned up {removed_count} records for missing files.")
        except IOError as e:
            print(f"Error saving cleaned records: {e}")
    else:
        print("No cleanup needed - all files exist.")


def main():
    parser = argparse.ArgumentParser(description='Manage UGC download records')
    parser.add_argument('command', choices=['list', 'summary', 'verify', 'cleanup'], 
                       help='Command to execute')
    parser.add_argument('--app-id', type=int, help='Filter by app ID')
    parser.add_argument('--status', choices=['downloaded', 'exists'], 
                       help='Filter by download status')
    
    args = parser.parse_args()
    
    # Load records
    records = load_records()
    
    if args.command == 'list':
        list_records(records, args.app_id, args.status)
    elif args.command == 'summary':
        show_summary(records)
    elif args.command == 'verify':
        verify_files(records)
    elif args.command == 'cleanup':
        cleanup_records(records)


if __name__ == "__main__":
    main()
