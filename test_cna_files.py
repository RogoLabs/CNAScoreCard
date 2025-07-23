#!/usr/bin/env python3

"""
CNA JSON Files Testing Script
Tests all individual CNA JSON files to identify data structure issues
"""

import json
import os
import sys
from pathlib import Path

def test_cna_json_file(file_path, short_name):
    """Test if a CNA JSON file exists and has valid structure"""
    results = {
        'short_name': short_name,
        'file_exists': False,
        'valid_json': False,
        'has_cna_info': False,
        'has_cna_scoring': False,
        'has_recent_cves': False,
        'error': None,
        'file_size': 0
    }
    
    try:
        # Check if file exists
        if not file_path.exists():
            results['error'] = 'File does not exist'
            return results
        
        results['file_exists'] = True
        results['file_size'] = file_path.stat().st_size
        
        # Try to parse JSON
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        results['valid_json'] = True
        
        # Check required structure
        if 'cna_info' in data:
            results['has_cna_info'] = True
            
        if 'cna_scoring' in data:
            results['has_cna_scoring'] = True
            
        if 'recent_cves' in data:
            results['has_recent_cves'] = True
            
        # Additional validation
        if results['has_cna_info']:
            cna_info = data['cna_info']
            if not isinstance(cna_info, dict):
                results['error'] = 'cna_info is not a dictionary'
                return results
                
        return results
        
    except json.JSONDecodeError as e:
        results['error'] = f'JSON parsing error: {str(e)}'
        return results
    except Exception as e:
        results['error'] = f'Unexpected error: {str(e)}'
        return results

def load_cna_list(combined_file_path):
    """Load list of CNAs from cna_combined.json"""
    try:
        with open(combined_file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        return [(cna['shortName'], cna.get('organizationName', ''), cna.get('rank', 0)) 
                for cna in data]
    except Exception as e:
        print(f"❌ Failed to load CNA list: {e}")
        sys.exit(1)

def main():
    print("🧪 CNA JSON Files Testing Script")
    print("=" * 50)
    
    # Paths
    script_dir = Path(__file__).parent
    web_dir = script_dir / 'web'
    cna_data_dir = web_dir / 'data' / 'cna'
    combined_file = web_dir / 'data' / 'cna_combined.json'
    
    # Load CNA list
    print("📋 Loading CNA list...")
    cnas = load_cna_list(combined_file)
    print(f"Found {len(cnas)} CNAs to test\n")
    
    # Test results
    results = []
    passed = 0
    failed = 0
    
    print("🔍 Testing individual CNA JSON files...")
    print("-" * 50)
    
    for short_name, org_name, rank in cnas:
        file_path = cna_data_dir / f"{short_name}.json"
        result = test_cna_json_file(file_path, short_name)
        results.append((result, org_name, rank))
        
        if result['error']:
            failed += 1
            print(f"❌ {short_name}: {result['error']}")
        else:
            passed += 1
            status_parts = []
            if result['has_cna_info']:
                status_parts.append("✓ cna_info")
            if result['has_cna_scoring']:
                status_parts.append("✓ scoring")
            if result['has_recent_cves']:
                status_parts.append("✓ recent_cves")
            
            size_kb = result['file_size'] / 1024
            print(f"✅ {short_name} ({size_kb:.1f}KB) - {', '.join(status_parts)}")
    
    # Generate report
    print("\n" + "=" * 60)
    print("📊 TEST REPORT")
    print("=" * 60)
    print(f"Total CNAs: {len(cnas)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/len(cnas)*100):.1f}%")
    
    # Detailed failure analysis
    failures = [(r, org, rank) for r, org, rank in results if r['error']]
    if failures:
        print(f"\n❌ FAILURES ({len(failures)}):")
        print("-" * 40)
        
        # Group by error type
        error_groups = {}
        for result, org_name, rank in failures:
            error_type = result['error'].split(':')[0]
            if error_type not in error_groups:
                error_groups[error_type] = []
            error_groups[error_type].append((result, org_name, rank))
        
        for error_type, group in error_groups.items():
            print(f"\n{error_type} ({len(group)} CNAs):")
            for result, org_name, rank in group[:10]:  # Show first 10
                print(f"  • Rank {rank}: {result['short_name']} ({org_name})")
                if len(group) > 10:
                    print(f"  ... and {len(group) - 10} more")
                    break
    
    # Structure analysis
    print(f"\n📊 STRUCTURE ANALYSIS:")
    print("-" * 30)
    
    valid_files = [r for r, _, _ in results if not r['error']]
    if valid_files:
        has_info = sum(1 for r in valid_files if r['has_cna_info'])
        has_scoring = sum(1 for r in valid_files if r['has_cna_scoring'])
        has_recent = sum(1 for r in valid_files if r['has_recent_cves'])
        
        print(f"Files with cna_info: {has_info}/{len(valid_files)} ({has_info/len(valid_files)*100:.1f}%)")
        print(f"Files with cna_scoring: {has_scoring}/{len(valid_files)} ({has_scoring/len(valid_files)*100:.1f}%)")
        print(f"Files with recent_cves: {has_recent}/{len(valid_files)} ({has_recent/len(valid_files)*100:.1f}%)")
    
    print("\n" + "=" * 60)
    
    # Return exit code based on results
    if failed > 0:
        print(f"⚠️  {failed} files have issues that need attention")
        return 1
    else:
        print("🎉 All CNA JSON files are valid!")
        return 0

if __name__ == "__main__":
    sys.exit(main())
