#!/usr/bin/env python3

"""
Debug Missing CNAs Script
Identifies why specific CNAs are missing from individual JSON generation
"""

import json
import os
from pathlib import Path
from collections import defaultdict

def load_json_file(file_path):
    """Load and parse a JSON file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return None

def main():
    print("🔍 Debug Missing CNAs Script")
    print("=" * 50)
    
    # Paths
    script_dir = Path(__file__).parent
    web_dir = script_dir / 'web'
    cna_combined_file = web_dir / 'data' / 'cna_combined.json'
    cna_data_dir = web_dir / 'data' / 'cna'
    
    # Load CNA combined data to get expected CNAs
    print("📋 Loading CNA combined data...")
    cna_combined = load_json_file(cna_combined_file)
    if not cna_combined:
        return 1
    
    # Get all expected CNA names
    expected_cnas = {cna['shortName']: cna for cna in cna_combined}
    print(f"Expected CNAs: {len(expected_cnas)}")
    
    # Check which JSON files exist
    print("\n📁 Checking individual CNA JSON files...")
    existing_files = set()
    missing_cnas = []
    
    for short_name in expected_cnas.keys():
        json_file = cna_data_dir / f"{short_name}.json"
        if json_file.exists():
            existing_files.add(short_name)
        else:
            missing_cnas.append(short_name)
    
    print(f"Existing JSON files: {len(existing_files)}")
    print(f"Missing JSON files: {len(missing_cnas)}")
    
    if missing_cnas:
        print(f"\n❌ MISSING CNAs ({len(missing_cnas)}):")
        for i, cna_name in enumerate(missing_cnas, 1):
            cna_info = expected_cnas[cna_name]
            org_name = cna_info.get('organizationName', 'N/A')
            rank = cna_info.get('rank', 'N/A')
            print(f"  {i:2d}. {cna_name} (Rank {rank}) - {org_name}")
    
    # Now let's investigate potential name mapping issues
    print(f"\n🔍 INVESTIGATING NAME MAPPING ISSUES:")
    print("-" * 50)
    
    # Load a sample of recent CVE data to see what assigningCna names exist
    cve_sample_file = web_dir / 'data' / 'cve_sample.json'  # This might not exist
    
    # Alternative: look for any CVE data files in the pipeline
    pipeline_dir = script_dir / 'cnascorecard_pipeline'
    
    # Check if we can find CVE data patterns
    print("Looking for CVE data patterns...")
    
    # For each missing CNA, let's check potential name variations
    print(f"\n📊 POTENTIAL NAME VARIATIONS FOR MISSING CNAs:")
    print("-" * 60)
    
    for cna_name in missing_cnas[:10]:  # Show first 10
        cna_info = expected_cnas[cna_name]
        org_name = cna_info.get('organizationName', '')
        
        print(f"\n🔍 {cna_name}:")
        print(f"   Organization: {org_name}")
        
        # Generate potential variations
        variations = set()
        
        # Original name
        variations.add(cna_name)
        
        # Remove underscores
        variations.add(cna_name.replace('_', ''))
        variations.add(cna_name.replace('_', ' '))
        variations.add(cna_name.replace('_', '-'))
        
        # Case variations
        variations.add(cna_name.lower())
        variations.add(cna_name.upper())
        
        # Organization name variations
        if org_name:
            # Extract potential short names from organization
            org_words = org_name.replace(',', '').replace('.', '').split()
            if len(org_words) > 0:
                variations.add(org_words[0])  # First word
                if len(org_words) > 1:
                    variations.add(''.join(word[0] for word in org_words))  # Acronym
        
        print(f"   Potential variations: {sorted(variations)}")
    
    # Check for filename sanitization issues
    print(f"\n🔧 FILENAME SANITIZATION CHECK:")
    print("-" * 40)
    
    import re
    
    def sanitize_filename(name):
        """Same sanitization logic as in pipeline"""
        sanitized = re.sub(r'[<>:"/\|?*]', '_', name)
        sanitized = re.sub(r'_{2,}', '_', sanitized)
        sanitized = sanitized.strip('_')
        return sanitized
    
    for cna_name in missing_cnas:
        sanitized = sanitize_filename(cna_name)
        if sanitized != cna_name:
            print(f"  {cna_name} → {sanitized}")
            
            # Check if sanitized version exists
            sanitized_file = cna_data_dir / f"{sanitized}.json"
            if sanitized_file.exists():
                print(f"    ✅ Sanitized file EXISTS: {sanitized}.json")
            else:
                print(f"    ❌ Sanitized file missing: {sanitized}.json")
    
    # Summary and recommendations
    print(f"\n📋 SUMMARY AND RECOMMENDATIONS:")
    print("=" * 50)
    print(f"• {len(missing_cnas)} CNAs are missing individual JSON files")
    print(f"• This represents {len(missing_cnas)/len(expected_cnas)*100:.1f}% of all CNAs")
    
    print(f"\n🔧 LIKELY ROOT CAUSES:")
    print("1. Name mismatch between CVE data 'assigningCna' and official CNA names")
    print("2. CNAs with no recent CVEs being filtered out in aggregation")
    print("3. Filename sanitization issues with special characters")
    print("4. CNAs not appearing in CVE data at all")
    
    print(f"\n🛠️  RECOMMENDED FIXES:")
    print("1. Add debug logging to aggregation.py to show CNA filtering")
    print("2. Implement robust name mapping between CVE data and official names")
    print("3. Ensure all official CNAs get JSON files even with zero CVEs")
    print("4. Add comprehensive validation to pipeline output")
    
    return 0

if __name__ == "__main__":
    exit(main())
