#!/usr/bin/env python3
"""
RFID JSON Validation Script

Validates generated JSON files for:
- Proper JSON format
- Required fields
- Temperature section completeness
- Data consistency
"""

import json
import glob
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

class RFIDJsonValidator:
    def __init__(self):
        # Core required fields from parse.py output
        self.required_fields = {
            'uid', 'filament_type', 'filament_color', 
            'spool_weight', 'filament_diameter', 'filename'
        }
        # Expected temperature fields (not all may be present)
        self.temperature_fields = {
            'min_hotend', 'max_hotend', 'bed_temp', 
            'bed_temp_type', 'drying_time', 'drying_temp'
        }
        # Common optional fields that shouldn't be missing in most cases
        self.common_fields = {
            'material_id', 'variant_id', 'detailed_filament_type',
            'spool_width', 'filament_length', 'tray_uid'
        }
        
    def validate_json_file(self, json_path: str) -> Dict[str, Any]:
        """Validate a single JSON file."""
        result = {
            'file': json_path,
            'valid': False,
            'errors': [],
            'warnings': []
        }
        
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
                
            # Check required fields
            missing_fields = self.required_fields - set(data.keys())
            if missing_fields:
                result['errors'].append(f"Missing required fields: {missing_fields}")
            
            # Validate temperature section
            if 'temperatures' in data:
                if isinstance(data['temperatures'], dict):
                    missing_temp_fields = self.temperature_fields - set(data['temperatures'].keys())
                    if missing_temp_fields:
                        result['warnings'].append(f"Missing temperature fields: {missing_temp_fields}")
                else:
                    result['errors'].append("Temperature section should be a dictionary")
            else:
                result['warnings'].append("No temperature section found")
            
            # Validate UID format
            if 'uid' in data:
                uid = data['uid']
                if not isinstance(uid, str) or len(uid) != 8:
                    result['errors'].append(f"UID should be 8-character string, got: {uid}")
                else:
                    try:
                        int(uid, 16)  # Check if valid hex
                    except ValueError:
                        result['errors'].append(f"UID should be valid hex string: {uid}")
            
            # Check if corresponding .bin file exists
            bin_path = json_path.replace('.json', '.bin')
            if not Path(bin_path).exists():
                result['warnings'].append(f"Corresponding .bin file not found: {bin_path}")
            
            # Set valid if no errors
            result['valid'] = len(result['errors']) == 0
            
        except json.JSONDecodeError as e:
            result['errors'].append(f"Invalid JSON format: {e}")
        except Exception as e:
            result['errors'].append(f"Error reading file: {e}")
            
        return result
    
    def validate_directory(self, directory: str) -> Dict[str, Any]:
        """Validate all JSON files in a directory."""
        json_files = glob.glob(f"{directory}/**/*.json", recursive=True)
        
        # Filter out key files
        rfid_json_files = [f for f in json_files if 'key' not in f.lower()]
        
        results = []
        valid_count = 0
        total_errors = 0
        total_warnings = 0
        
        for json_file in rfid_json_files:
            result = self.validate_json_file(json_file)
            results.append(result)
            
            if result['valid']:
                valid_count += 1
            
            total_errors += len(result['errors'])
            total_warnings += len(result['warnings'])
        
        summary = {
            'total_files': len(rfid_json_files),
            'valid_files': valid_count,
            'invalid_files': len(rfid_json_files) - valid_count,
            'total_errors': total_errors,
            'total_warnings': total_warnings,
            'results': results
        }
        
        return summary
    
    def print_validation_report(self, summary: Dict[str, Any]) -> None:
        """Print a formatted validation report."""
        print(f"\n🔍 RFID JSON Validation Report")
        print(f"{'=' * 50}")
        print(f"📊 Total Files: {summary['total_files']}")
        print(f"✅ Valid Files: {summary['valid_files']}")
        print(f"❌ Invalid Files: {summary['invalid_files']}")
        print(f"🚨 Total Errors: {summary['total_errors']}")
        print(f"⚠️  Total Warnings: {summary['total_warnings']}")
        
        if summary['invalid_files'] > 0:
            print(f"\n❌ Files with Errors:")
            for result in summary['results']:
                if not result['valid']:
                    print(f"  📄 {result['file']}")
                    for error in result['errors']:
                        print(f"    ❌ {error}")
        
        if summary['total_warnings'] > 0:
            print(f"\n⚠️  Files with Warnings:")
            warning_files = [r for r in summary['results'] if r['warnings']]
            for result in warning_files[:5]:  # Show first 5
                print(f"  📄 {result['file']}")
                for warning in result['warnings']:
                    print(f"    ⚠️  {warning}")
            
            if len(warning_files) > 5:
                print(f"    ... and {len(warning_files) - 5} more files with warnings")
        
        print(f"\n{'=' * 50}")
        
        if summary['invalid_files'] == 0:
            print("🎉 All JSON files are valid!")
        else:
            print(f"🔧 {summary['invalid_files']} files need attention")

def main():
    """Main validation function."""
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        directory = "."
    
    if not Path(directory).exists():
        print(f"Error: Directory '{directory}' does not exist")
        sys.exit(1)
    
    validator = RFIDJsonValidator()
    summary = validator.validate_directory(directory)
    validator.print_validation_report(summary)
    
    # Set exit code based on validation results
    if summary['invalid_files'] > 0:
        sys.exit(1)  # Exit with error if invalid files found
    else:
        sys.exit(0)  # Success

if __name__ == "__main__":
    main()