#!/usr/bin/env python3
"""
Generate Encrypted Proxmark3 JSON Files

Converts binary RFID dumps to Proxmark3 JSON format with encrypted hex blocks.
This generates the encrypted JSON files that preserve the raw hex dump format
used by Proxmark3 and other RFID tools, rather than human-readable decrypted content.
"""

import os
import json
import glob
import sys
from pathlib import Path
from typing import Dict, Any, Optional

def extract_sector_keys_from_blocks(blocks: Dict[str, str]) -> Dict[str, Any]:
    """Extract SectorKeys from sector trailer blocks."""
    sector_keys = {}
    
    # MIFARE Classic 1K has 16 sectors (0-15)
    for sector in range(16):
        sector_trailer_block = sector * 4 + 3  # Sector trailer is always the 4th block in each sector
        
        if str(sector_trailer_block) not in blocks:
            continue
            
        trailer_hex = blocks[str(sector_trailer_block)]
        if len(trailer_hex) != 32:  # 16 bytes = 32 hex chars
            continue
            
        # Extract keys and access conditions from sector trailer
        # Structure: KeyA (6 bytes) + Access (4 bytes) + KeyB (6 bytes) 
        key_a = trailer_hex[0:12]   # First 6 bytes (12 hex chars)
        access_conditions = trailer_hex[12:20]  # Next 4 bytes (8 hex chars) 
        key_b = trailer_hex[20:32]  # Last 6 bytes (12 hex chars)
        
        # Generate access conditions text (simplified version)
        access_text = generate_access_conditions_text(access_conditions, sector)
        
        sector_keys[str(sector)] = {
            "KeyA": key_a,
            "KeyB": key_b,
            "AccessConditions": access_conditions,
            "AccessConditionsText": access_text
        }
    
    return sector_keys

def generate_access_conditions_text(access_conditions: str, sector: int) -> Dict[str, str]:
    """Generate human-readable access conditions text."""
    # This is a simplified implementation
    # Real access conditions parsing is complex, but most Bambu tags use standard conditions
    
    base_block = sector * 4
    user_data = access_conditions[-2:]  # Last byte as user data
    
    return {
        f"block{base_block}": "read AB",
        f"block{base_block + 1}": "read AB", 
        f"block{base_block + 2}": "read AB",
        f"block{base_block + 3}": "read ACCESS by AB; write ACCESS by B",
        "UserData": user_data
    }

def bin_to_proxmark3_json(bin_file: str) -> Dict[str, Any]:
    """Convert a binary RFID dump to Proxmark3 JSON format."""
    try:
        with open(bin_file, 'rb') as f:
            data = f.read()
        
        # Ensure we have the expected 1KB (1024 bytes) for MIFARE Classic 1K
        if len(data) != 1024:
            print(f"Warning: {bin_file} has {len(data)} bytes, expected 1024")
            return None
        
        # Extract UID from first block (first 4 bytes)
        uid = data[0:4].hex().upper()
        
        # Create blocks dictionary - 64 blocks of 16 bytes each
        blocks = {}
        for block_num in range(64):
            start_pos = block_num * 16
            end_pos = start_pos + 16
            block_data = data[start_pos:end_pos]
            blocks[str(block_num)] = block_data.hex().upper()
        
        # Extract SectorKeys from the blocks
        sector_keys = extract_sector_keys_from_blocks(blocks)
        
        # Standard MIFARE Classic 1K values
        proxmark3_json = {
            "Created": "proxmark3",
            "FileType": "mfc v2",
            "Card": {
                "UID": uid,
                "ATQA": "0400",  # Standard for MIFARE Classic 1K
                "SAK": "08"      # Standard for MIFARE Classic 1K
            },
            "blocks": blocks,
            "SectorKeys": sector_keys
        }
        
        return proxmark3_json
        
    except Exception as e:
        print(f"Error processing {bin_file}: {e}")
        return None

def find_all_bin_files(directory: str) -> list:
    """Find all .bin files recursively, excluding key files."""
    pattern = os.path.join(directory, "**/*.bin")
    bin_files = glob.glob(pattern, recursive=True)
    # Exclude key files and other non-dump files
    bin_files = [f for f in bin_files if 'key' not in f.lower() and 'nonce' not in f.lower()]
    return sorted(bin_files)

def generate_encrypted_json_file(bin_file: str, force: bool = False) -> bool:
    """Generate encrypted JSON file from binary dump."""
    # Handle files that already have -dump in the name
    if bin_file.endswith('-dump.bin'):
        json_file = bin_file.replace('-dump.bin', '-dump.json')
    else:
        json_file = bin_file.replace('.bin', '-dump.json')
    
    # Check if file already exists and not forcing regeneration
    if os.path.exists(json_file) and not force:
        # Check if existing file is already in Proxmark3 format
        try:
            with open(json_file, 'r') as f:
                existing_data = json.load(f)
                if existing_data.get("Created") == "proxmark3" and "blocks" in existing_data:
                    print(f"✅ Already encrypted format: {json_file}")
                    return True
        except (json.JSONDecodeError, FileNotFoundError):
            pass
    
    print(f"Processing: {bin_file}")
    
    # Convert to Proxmark3 format
    proxmark3_data = bin_to_proxmark3_json(bin_file)
    if proxmark3_data is None:
        print(f"❌ Failed to process: {bin_file}")
        return False
    
    # Write JSON file
    try:
        with open(json_file, 'w') as f:
            json.dump(proxmark3_data, f, indent=2)
        
        print(f"✅ Generated: {json_file}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to write {json_file}: {e}")
        return False

def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate encrypted Proxmark3 JSON files from RFID binary dumps')
    parser.add_argument('directory', nargs='?', default='.',
                       help='Directory to process (default: current directory)')
    parser.add_argument('--force', action='store_true',
                       help='Force regenerate all JSON files, even if they exist')
    parser.add_argument('--specific-file', 
                       help='Generate JSON for a specific .bin file only')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be processed without actually generating files')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.directory):
        print(f"Error: Directory '{args.directory}' does not exist")
        sys.exit(1)
    
    print(f"🔐 Encrypted JSON Generator (Proxmark3 Format)")
    print(f"Directory: {args.directory}")
    print(f"Force regenerate: {args.force}")
    print()
    
    if args.specific_file:
        # Process specific file
        if not os.path.exists(args.specific_file):
            print(f"Error: File '{args.specific_file}' not found")
            sys.exit(1)
        
        if args.dry_run:
            print(f"Would process: {args.specific_file}")
        else:
            success = generate_encrypted_json_file(args.specific_file, args.force)
            if success:
                print("✅ Generation completed successfully")
            else:
                print("❌ Generation failed")
                sys.exit(1)
    else:
        # Process all bin files
        bin_files = find_all_bin_files(args.directory)
        
        print(f"Found {len(bin_files)} binary files to process")
        
        if not bin_files:
            print("✅ No binary files found!")
            return
        
        if args.dry_run:
            print("\nFiles that would be processed:")
            for bin_file in bin_files:
                # Handle files that already have -dump in the name
                if bin_file.endswith('-dump.bin'):
                    json_file = bin_file.replace('-dump.bin', '-dump.json')
                else:
                    json_file = bin_file.replace('.bin', '-dump.json')
                print(f"  {bin_file} -> {json_file}")
            return
        
        # Generate encrypted JSON files
        print("\nGenerating encrypted JSON files...")
        generated_count = 0
        failed_count = 0
        skipped_count = 0
        
        for bin_file in bin_files:
            # Handle files that already have -dump in the name
            if bin_file.endswith('-dump.bin'):
                json_file = bin_file.replace('-dump.bin', '-dump.json')
            else:
                json_file = bin_file.replace('.bin', '-dump.json')
            
            # Check if already in correct format
            if os.path.exists(json_file) and not args.force:
                try:
                    with open(json_file, 'r') as f:
                        existing_data = json.load(f)
                        if existing_data.get("Created") == "proxmark3" and "blocks" in existing_data:
                            skipped_count += 1
                            continue
                except (json.JSONDecodeError, FileNotFoundError):
                    pass
            
            if generate_encrypted_json_file(bin_file, args.force):
                generated_count += 1
            else:
                failed_count += 1
        
        print(f"\n📊 Generation Summary:")
        print(f"✅ Successfully generated: {generated_count}")
        print(f"⏭️  Already encrypted (skipped): {skipped_count}")
        print(f"❌ Failed: {failed_count}")
        print(f"📁 Total processed: {len(bin_files)}")
        
        # Calculate success rate
        total_processed = generated_count + failed_count
        if total_processed > 0:
            success_rate = (generated_count / total_processed * 100)
            print(f"📊 Success rate: {success_rate:.1f}%")
        
        if failed_count > 0:
            print(f"\n⚠️  {failed_count} files failed to generate")
            print(f"✅ {generated_count} files generated successfully")
            sys.exit(1)
        else:
            print(f"\n🎉 All encrypted JSON files generated successfully!")

if __name__ == "__main__":
    main()