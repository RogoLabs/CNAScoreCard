#!/usr/bin/env python3
"""
Comprehensive analysis of 2025 CVEs to identify CNAs not in official list.
Generates detailed JSON report with CNA names and their associated CVEs.
"""

import json
import os
import glob
from collections import defaultdict
from datetime import datetime
import sys

def load_official_cnas():
    """Load the official CNA list."""
    try:
        with open('/Users/gamblin/Documents/Github/CNAScoreCard/web/data/cna_list.json', 'r') as f:
            official_cnas = json.load(f)
        
        official_shortnames = set()
        for cna in official_cnas:
            if 'shortName' in cna:
                official_shortnames.add(cna['shortName'])
        
        print(f"✅ Loaded {len(official_shortnames)} official CNAs")
        return official_shortnames
    except Exception as e:
        print(f"❌ Error loading official CNA list: {e}")
        return set()

def is_2025_cve(cve_data):
    """Check if CVE was published in 2025."""
    try:
        date_published = cve_data.get('cveMetadata', {}).get('datePublished', '')
        if date_published:
            # Parse ISO date format
            pub_date = datetime.fromisoformat(date_published.replace('Z', '+00:00'))
            return pub_date.year == 2025
    except Exception:
        pass
    return False

def extract_cna_info(cve_data):
    """Extract CNA shortname and other relevant info from CVE."""
    cna_info = {
        'shortName': None,
        'orgName': None,
        'datePublished': None
    }
    
    try:
        # Extract CNA shortname
        if 'containers' in cve_data and 'cna' in cve_data['containers']:
            provider_metadata = cve_data['containers']['cna'].get('providerMetadata', {})
            cna_info['shortName'] = provider_metadata.get('shortName', '').strip()
            cna_info['orgName'] = provider_metadata.get('orgName', '').strip()
        
        # Extract published date
        cna_info['datePublished'] = cve_data.get('cveMetadata', {}).get('datePublished', '')
        
    except Exception as e:
        print(f"Warning: Error extracting CNA info: {e}")
    
    return cna_info

def analyze_2025_cves():
    """Analyze all 2025 CVEs for CNA validation issues."""
    print("🔍 Starting comprehensive 2025 CVE analysis...")
    
    # Load official CNA list
    official_cnas = load_official_cnas()
    if not official_cnas:
        print("❌ Cannot proceed without official CNA list")
        return
    
    # Initialize tracking variables
    unofficial_cnas = defaultdict(list)
    missing_cnas = []
    invalid_cnas = defaultdict(list)
    total_2025_cves = 0
    total_files_processed = 0
    
    # Process all 2025 CVE files
    cve_base_dir = '/Users/gamblin/Documents/Github/CNAScoreCard/cve_data/cves/2025'
    
    if not os.path.exists(cve_base_dir):
        print(f"❌ CVE directory not found: {cve_base_dir}")
        return
    
    print(f"📁 Scanning CVE directory: {cve_base_dir}")
    
    # Get all subdirectories
    subdirs = [d for d in os.listdir(cve_base_dir) if os.path.isdir(os.path.join(cve_base_dir, d))]
    print(f"📂 Found {len(subdirs)} subdirectories: {sorted(subdirs)}")
    
    for subdir in subdirs:
        subdir_path = os.path.join(cve_base_dir, subdir)
        pattern = os.path.join(subdir_path, '*.json')
        cve_files = glob.glob(pattern)
        
        print(f"📄 Processing {len(cve_files)} files in {subdir}...")
        
        for filepath in cve_files:
            try:
                total_files_processed += 1
                
                with open(filepath, 'r') as f:
                    cve_data = json.load(f)
                
                # Check if this is a 2025 CVE by published date
                if not is_2025_cve(cve_data):
                    continue
                
                total_2025_cves += 1
                filename = os.path.basename(filepath)
                cve_id = filename.replace('.json', '')
                
                # Extract CNA information
                cna_info = extract_cna_info(cve_data)
                cna_shortname = cna_info['shortName']
                
                # Categorize the CVE based on CNA status
                if not cna_shortname:
                    missing_cnas.append({
                        'cve_id': cve_id,
                        'date_published': cna_info['datePublished']
                    })
                elif len(cna_shortname) < 2:
                    invalid_cnas['too_short'].append({
                        'cve_id': cve_id,
                        'cna_shortname': cna_shortname,
                        'date_published': cna_info['datePublished']
                    })
                elif any(char in cna_shortname for char in ['<', '>', '&', '"', "'"]):
                    invalid_cnas['special_chars'].append({
                        'cve_id': cve_id,
                        'cna_shortname': cna_shortname,
                        'date_published': cna_info['datePublished']
                    })
                elif cna_shortname.lower() in ['unknown', 'n/a', 'none', 'null', 'tbd', 'pending']:
                    invalid_cnas['placeholder'].append({
                        'cve_id': cve_id,
                        'cna_shortname': cna_shortname,
                        'date_published': cna_info['datePublished']
                    })
                elif cna_shortname not in official_cnas:
                    # This is an unofficial CNA
                    unofficial_cnas[cna_shortname].append({
                        'cve_id': cve_id,
                        'date_published': cna_info['datePublished']
                    })
                
                # Progress indicator
                if total_files_processed % 1000 == 0:
                    print(f"  📊 Processed {total_files_processed} files, found {total_2025_cves} 2025 CVEs...")
                    
            except Exception as e:
                print(f"❌ Error processing {os.path.basename(filepath)}: {e}")
    
    # Generate comprehensive report
    print(f"\n📊 ANALYSIS COMPLETE")
    print(f"Total files processed: {total_files_processed:,}")
    print(f"Total 2025 CVEs found: {total_2025_cves:,}")
    print(f"CVEs with missing CNA shortnames: {len(missing_cnas)}")
    print(f"CVEs with invalid CNA patterns: {sum(len(v) for v in invalid_cnas.values())}")
    print(f"CVEs from unofficial CNAs: {sum(len(v) for v in unofficial_cnas.values())}")
    print(f"Number of unofficial CNAs: {len(unofficial_cnas)}")
    
    # Create detailed JSON report
    report = {
        'analysis_metadata': {
            'analysis_date': datetime.now().isoformat(),
            'total_files_processed': total_files_processed,
            'total_2025_cves': total_2025_cves,
            'official_cnas_count': len(official_cnas)
        },
        'summary': {
            'missing_cna_shortnames': len(missing_cnas),
            'invalid_cna_patterns': sum(len(v) for v in invalid_cnas.values()),
            'unofficial_cnas_count': len(unofficial_cnas),
            'unofficial_cves_count': sum(len(v) for v in unofficial_cnas.values())
        },
        'unofficial_cnas': dict(unofficial_cnas),
        'missing_cnas': missing_cnas,
        'invalid_cnas': dict(invalid_cnas)
    }
    
    # Save report
    report_filename = f'cve_2025_cna_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n📄 Detailed report saved to: {report_filename}")
    
    # Display summary of unofficial CNAs
    if unofficial_cnas:
        print(f"\n🔍 UNOFFICIAL CNAs FOUND ({len(unofficial_cnas)} CNAs):")
        sorted_unofficial = sorted(unofficial_cnas.items(), key=lambda x: len(x[1]), reverse=True)
        
        for cna_name, cves in sorted_unofficial:
            print(f"  📌 {cna_name}: {len(cves)} CVEs")
            # Show first few CVE IDs as examples
            example_cves = [cve['cve_id'] for cve in cves[:3]]
            print(f"     Examples: {', '.join(example_cves)}")
            if len(cves) > 3:
                print(f"     ... and {len(cves) - 3} more")
    
    return report

if __name__ == "__main__":
    try:
        report = analyze_2025_cves()
        print(f"\n✅ Analysis completed successfully!")
    except KeyboardInterrupt:
        print(f"\n⚠️  Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        sys.exit(1)
