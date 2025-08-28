#!/usr/bin/env python3
"""
Local RFID JSON Generator

A local testing script for generating JSON files from RFID .bin dumps.
This mirrors the logic used in the CI workflow but can be run locally for development.
"""

import os
import json
import subprocess
import sys
import glob
from pathlib import Path
from typing import List, Dict, Any

def yaml_to_json(yaml_output: str) -> Dict[str, Any]:
    """
    Convert YAML-like parse.py output to proper JSON.
    This matches the conversion logic used in the CI workflow.
    """
    lines = yaml_output.strip().split('\n')
    data = {}
    i = 0
    
    while i < len(lines):
        line = lines[i].strip()
        if not line or line.startswith('#'):
            i += 1
            continue
        
        # Handle lines that start with "- " (YAML list items)
        if line.startswith('- ') and ': ' in line:
            line = line[2:]  # Remove "- " prefix
            key_val, value = line.split(': ', 1)
            key = key_val.strip()
            value = value.strip()
            
            # Handle nested temperatures section
            if key == 'temperatures' and not value:  # temperatures: (empty value)
                data['temperatures'] = {}
                i += 1
                # Look for indented temperature fields with "  - " prefix
                while i < len(lines) and lines[i].startswith('  - '):
                    temp_line = lines[i][4:]  # Remove '  - '
                    if ': ' in temp_line:
                        temp_key, temp_val = temp_line.split(': ', 1)
                        temp_key = temp_key.strip()
                        temp_val = temp_val.strip()
                        # Convert bed_temp_type to int
                        if temp_key == 'bed_temp_type':
                            try:
                                temp_val = int(temp_val)
                            except ValueError:
                                pass  # Keep as string if conversion fails
                        data['temperatures'][temp_key] = temp_val
                    i += 1
                continue
            
            # Handle other fields
            if value.isdigit():
                data[key] = int(value)
            elif value.lower() == 'true':
                data[key] = True
            elif value.lower() == 'false':
                data[key] = False
            else:
                data[key] = value
        
        elif ': ' in line and not line.startswith('-'):
            # Handle regular key: value lines
            key_val, value = line.split(': ', 1)
            key = key_val.strip()
            value = value.strip()
            
            # Handle nested temperatures section
            if key == 'temperatures' and not value:  # temperatures: (empty value)
                data['temperatures'] = {}
                i += 1
                # Look for indented temperature fields with "  - " prefix
                while i < len(lines) and lines[i].startswith('  - '):
                    temp_line = lines[i][4:]  # Remove '  - '
                    if ': ' in temp_line:
                        temp_key, temp_val = temp_line.split(': ', 1)
                        temp_key = temp_key.strip()
                        temp_val = temp_val.strip()
                        # Convert bed_temp_type to int
                        if temp_key == 'bed_temp_type':
                            try:
                                temp_val = int(temp_val)
                            except ValueError:
                                pass  # Keep as string if conversion fails
                        data['temperatures'][temp_key] = temp_val
                    i += 1
                continue
            
            # Handle other fields
            if value.isdigit():
                data[key] = int(value)
            elif value.lower() == 'true':
                data[key] = True
            elif value.lower() == 'false':
                data[key] = False
            else:
                data[key] = value
        
        i += 1
    
    return data

def generate_json_for_bin(bin_file: str, parse_script: str = 'parse.py') -> bool:
    """Generate JSON for a single .bin file."""
    try:
        print(f"Processing: {bin_file}")
        
        # Check if parse.py exists
        if not os.path.exists(parse_script):
            print(f"Error: {parse_script} not found")
            return False
        
        # Run parse.py on the .bin file
        result = subprocess.run(
            ['python3', parse_script, bin_file],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.dirname(parse_script) or '.'
        )
        
        if result.returncode != 0:
            print(f"Error parsing {bin_file}:")
            print(f"  stdout: {result.stdout}")
            print(f"  stderr: {result.stderr}")
            return False
        
        # Convert YAML-like output to JSON
        json_data = yaml_to_json(result.stdout)
        
        # Add filename for reference
        json_data['filename'] = bin_file
        
        # Write JSON file
        json_file = bin_file.replace('.bin', '.json')
        with open(json_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"✅ Generated: {json_file}")
        return True
        
    except subprocess.TimeoutExpired:
        print(f"❌ Timeout processing {bin_file}")
        return False
    except Exception as e:
        print(f"❌ Failed to process {bin_file}: {e}")
        return False

def is_encrypted_json(json_path: str) -> bool:
    """Check if JSON file contains encrypted Proxmark3 format data."""
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
            # Encrypted JSON files have Proxmark3 structure with blocks
            return (data.get("Created") == "proxmark3" or 
                    "blocks" in data or 
                    data.get("FileType") == "mfc v2")
    except (json.JSONDecodeError, FileNotFoundError):
        return False

def find_missing_json_files(directory: str, force_regenerate: bool = False) -> List[str]:
    """Find .bin files that don't have corresponding .json files.
    
    Note: Never overwrites existing encrypted JSON files, even with force_regenerate=True.
    Encrypted JSON files (Proxmark3 format) are preserved to maintain original dump data.
    """
    missing_files = []
    
    # Find all .bin files, excluding key files
    pattern = os.path.join(directory, "**/*.bin")
    bin_files = glob.glob(pattern, recursive=True)
    bin_files = [f for f in bin_files if 'key' not in f.lower()]
    
    for bin_file in bin_files:
        json_file = bin_file.replace('.bin', '.json')
        
        # Only process if no JSON exists, OR if force_regenerate AND it's not encrypted format
        if not os.path.exists(json_file):
            missing_files.append(bin_file)
        elif force_regenerate and not is_encrypted_json(json_file):
            # Only regenerate if it's not an encrypted Proxmark3 format file
            missing_files.append(bin_file)
    
    return missing_files

def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate JSON files from RFID .bin dumps')
    parser.add_argument('directory', nargs='?', default='.',
                       help='Directory to process (default: current directory)')
    parser.add_argument('--force', action='store_true',
                       help='Force regenerate all JSON files, not just missing ones')
    parser.add_argument('--parse-script', default='parse.py',
                       help='Path to parse.py script (default: parse.py in target directory)')
    parser.add_argument('--specific-file', 
                       help='Generate JSON for a specific .bin file only')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be processed without actually generating files')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.directory):
        print(f"Error: Directory '{args.directory}' does not exist")
        sys.exit(1)
    
    # Set parse script path relative to target directory if not absolute
    parse_script = args.parse_script
    if not os.path.isabs(parse_script):
        parse_script = os.path.join(args.directory, parse_script)
    
    if not os.path.exists(parse_script):
        print(f"Error: Parse script '{parse_script}' not found")
        print(f"Make sure parse.py is available in the RFID library directory")
        sys.exit(1)
    
    print(f"🔍 RFID JSON Generator")
    print(f"Directory: {args.directory}")
    print(f"Parse script: {parse_script}")
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
            success = generate_json_for_bin(args.specific_file, parse_script)
            if success:
                print("✅ Generation completed successfully")
            else:
                print("❌ Generation failed")
                sys.exit(1)
    else:
        # Process missing files
        missing_files = find_missing_json_files(args.directory, args.force)
        
        print(f"Found {len(missing_files)} files needing JSON generation")
        
        if not missing_files:
            print("✅ All .bin files have corresponding .json files!")
            print(f"\n📊 Generation Summary:")
            print(f"✅ Successfully generated: 0")
            print(f"❌ Failed: 0")
            print(f"📁 Total processed: 0")
            print(f"\n🎉 All JSON files are up to date!")
            return
        
        if args.dry_run:
            print("\nFiles that would be processed:")
            for bin_file in missing_files:
                json_file = bin_file.replace('.bin', '.json')
                print(f"  {bin_file} -> {json_file}")
            return
        
        # Generate JSON files
        print("\nGenerating JSON files...")
        generated_count = 0
        failed_count = 0
        
        for bin_file in missing_files:
            if generate_json_for_bin(bin_file, parse_script):
                generated_count += 1
            else:
                failed_count += 1
        
        print(f"\n📊 Generation Summary:")
        print(f"✅ Successfully generated: {generated_count}")
        print(f"❌ Failed: {failed_count}")
        print(f"📁 Total processed: {len(missing_files)}")
        
        # Always output success rate for workflow parsing
        total_files = generated_count + failed_count
        success_rate = (generated_count/total_files*100) if total_files > 0 else 100.0
        print(f"📊 Success rate: {success_rate:.1f}%")
        
        if failed_count > 0:
            print(f"\n⚠️  {failed_count} files failed to generate")
            print(f"✅ {generated_count} files generated successfully")
            # Don't exit with error - partial success is acceptable  
        else:
            print(f"\n🎉 All JSON files generated successfully!")

if __name__ == "__main__":
    main()