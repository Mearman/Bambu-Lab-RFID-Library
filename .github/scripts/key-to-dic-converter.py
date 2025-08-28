#!/usr/bin/env python3
"""
RFID Key.bin to .dic Converter

Converts binary RFID key files (.bin) to dictionary format (.dic) files.
Each key.bin contains 16 keys of 6 bytes each (12 hex characters per key).
"""

import os
import sys
import glob
from pathlib import Path
from typing import List, Dict, Any

def convert_key_bin_to_dic(key_bin_path: str) -> bool:
    """Convert a single key.bin file to .dic format."""
    try:
        print(f"Processing: {key_bin_path}")
        
        # Read binary key file
        with open(key_bin_path, 'rb') as f:
            key_data = f.read()
        
        # Validate file size (should be 192 bytes for 16 keys)
        if len(key_data) < 96:  # At least 16 keys * 6 bytes
            print(f"Warning: {key_bin_path} is smaller than expected ({len(key_data)} bytes)")
        
        # Extract keys (6 bytes each, skip zero padding)
        keys = []
        for i in range(0, len(key_data), 6):
            key_bytes = key_data[i:i+6]
            
            # Skip if key is all zeros (padding)
            if key_bytes == b'\x00\x00\x00\x00\x00\x00':
                continue
                
            # Convert to hex string (uppercase, no separators)
            hex_key = key_bytes.hex().upper()
            if len(hex_key) == 12:  # Valid 6-byte key
                keys.append(hex_key)
        
        if not keys:
            print(f"No valid keys found in {key_bin_path}")
            return False
        
        # Generate .dic file path
        dic_path = key_bin_path.replace('.bin', '.dic')
        
        # Write .dic file
        with open(dic_path, 'w') as f:
            for key in keys:
                f.write(key + '\n')
        
        print(f"✅ Generated: {dic_path} ({len(keys)} keys)")
        return True
        
    except Exception as e:
        print(f"❌ Failed to process {key_bin_path}: {e}")
        return False

def find_missing_dic_files(directory: str, force_regenerate: bool = False) -> List[str]:
    """Find key.bin files that don't have corresponding .dic files."""
    missing_files = []
    
    # Find all key.bin files
    pattern = os.path.join(directory, "**/*key*.bin")
    key_bin_files = glob.glob(pattern, recursive=True)
    
    for key_bin_file in key_bin_files:
        dic_file = key_bin_file.replace('.bin', '.dic')
        
        if force_regenerate or not os.path.exists(dic_file):
            missing_files.append(key_bin_file)
    
    return missing_files

def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Convert RFID key.bin files to .dic format')
    parser.add_argument('directory', nargs='?', default='.',
                       help='Directory to process (default: current directory)')
    parser.add_argument('--force', action='store_true',
                       help='Force regenerate all .dic files, not just missing ones')
    parser.add_argument('--specific-file', 
                       help='Convert a specific key.bin file only')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be processed without actually converting files')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.directory):
        print(f"Error: Directory '{args.directory}' does not exist")
        sys.exit(1)
    
    print(f"🔑 RFID Key.bin to .dic Converter")
    print(f"Directory: {args.directory}")
    print(f"Force regenerate: {args.force}")
    print()
    
    if args.specific_file:
        # Process specific file
        if not os.path.exists(args.specific_file):
            print(f"Error: File '{args.specific_file}' not found")
            sys.exit(1)
        
        if args.dry_run:
            dic_file = args.specific_file.replace('.bin', '.dic')
            print(f"Would process: {args.specific_file} -> {dic_file}")
        else:
            success = convert_key_bin_to_dic(args.specific_file)
            if success:
                print("✅ Conversion completed successfully")
            else:
                print("❌ Conversion failed")
                sys.exit(1)
    else:
        # Process missing files
        missing_files = find_missing_dic_files(args.directory, args.force)
        
        print(f"Found {len(missing_files)} key.bin files needing .dic conversion")
        
        if not missing_files:
            print("✅ All key.bin files have corresponding .dic files!")
            return
        
        if args.dry_run:
            print("\nFiles that would be processed:")
            for key_bin_file in missing_files:
                dic_file = key_bin_file.replace('.bin', '.dic')
                print(f"  {key_bin_file} -> {dic_file}")
            return
        
        # Convert key files
        print("\nConverting key.bin files...")
        converted_count = 0
        failed_count = 0
        
        for key_bin_file in missing_files:
            if convert_key_bin_to_dic(key_bin_file):
                converted_count += 1
            else:
                failed_count += 1
        
        print(f"\n📊 Conversion Summary:")
        print(f"✅ Successfully converted: {converted_count}")
        print(f"❌ Failed: {failed_count}")
        print(f"📁 Total processed: {len(missing_files)}")
        
        if failed_count > 0:
            print(f"\n⚠️  {failed_count} files failed to convert")
            print(f"✅ {converted_count} files converted successfully")  
            print(f"📊 Success rate: {(converted_count/(converted_count+failed_count)*100):.1f}%")
            # Don't exit with error - partial success is acceptable
        else:
            print(f"\n🎉 All .dic files generated successfully!")

if __name__ == "__main__":
    main()