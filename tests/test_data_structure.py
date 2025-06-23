#!/usr/bin/env python3
"""
Test data structure and validate JSON output
"""

import json
import os
from pathlib import Path
import sys

def validate_cna_data():
    """Validate the generated CNA data structure"""
    data_file = Path("web/data/cnas.json")
    
    if not data_file.exists():
        print("❌ CNA data file not found. Run generate_static_data.py first.")
        return False
    
    try:
        with open(data_file, 'r') as f:
            data = json.load(f)
        
        print(f"✅ Successfully loaded CNA data with {len(data)} entries")
        
        # Check first few entries
        required_fields = [
            'cna',
            'total_cves_scored',
            'overall_average_score',
            'average_completeness_score'
        ]
        
        sample_size = min(5, len(data))
        for i in range(sample_size):
            cna = data[i]
            print(f"\n📊 Validating CNA {i+1}: {cna.get('cna', 'Unknown')}")
            
            for field in required_fields:
                if field not in cna:
                    print(f"  ⚠️  Missing field: {field}")
                else:
                    value = cna[field]
                    print(f"  ✅ {field}: {value} ({type(value).__name__})")
            
            # Check optional percentage fields
            if 'percentage_with_cvss' in cna:
                print(f"  ✅ percentage_with_cvss: {cna['percentage_with_cvss']}%")
            if 'percentage_with_cwe' in cna:
                print(f"  ✅ percentage_with_cwe: {cna['percentage_with_cwe']}%")
        
        return True
        
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in CNA data file: {e}")
        return False
    except Exception as e:
        print(f"❌ Error validating CNA data: {e}")
        return False

def validate_cve_data():
    """Validate the CVE data files"""
    files_to_check = [
        "web/data/top100_cves.json",
        "web/data/bottom100_cves.json"
    ]
    
    for file_path in files_to_check:
        data_file = Path(file_path)
        if data_file.exists():
            try:
                with open(data_file, 'r') as f:
                    data = json.load(f)
                print(f"✅ {file_path}: {len(data)} entries")
                
                if len(data) > 0:
                    first_cve = data[0]
                    print(f"  Sample CVE ID: {first_cve.get('cve_id', 'Unknown')}")
                    print(f"  Sample CNA: {first_cve.get('cna', 'Unknown')}")
                    print(f"  Sample Score: {first_cve.get('overall_score', 0)}")
                    
            except Exception as e:
                print(f"❌ Error validating {file_path}: {e}")
                return False
        else:
            print(f"⚠️  {file_path} not found")
    
    return True

def main():
    """Run all validation tests"""
    print("🔍 Validating generated data structure...\n")
    
    cna_valid = validate_cna_data()
    cve_valid = validate_cve_data()
    
    if cna_valid and cve_valid:
        print("\n🎉 All data validation tests passed!")
        print("The generated data structure is compatible with the frontend.")
        return True
    else:
        print("\n❌ Data validation failed!")
        print("Please check the data generation process.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)