#!/usr/bin/env python3
"""
Script to download and process CNAsList.json to extract CNA metadata
and merge it with existing CNA data files.
"""

import json
import requests
import os
from pathlib import Path

def download_cna_list():
    """Download the latest CNAsList.json from the CVE Project website."""
    url = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error downloading CNAsList.json: {e}")
        return None

def normalize_cna_name(name):
    """Normalize CNA names for matching."""
    # Convert to lowercase and remove common suffixes/prefixes
    normalized = name.lower().strip()
    
    # Handle common variations
    variations = {
        'github_m': 'github',
        'github_p': 'github',
        'redhat-cnalr': 'red hat',
        'ncsc.ch': 'ncsc-ch',
        'cert-in': 'cert-in',
        'cert-pl': 'cert-pl',
        'tr-cert': 'tr-cert',
        'sk-cert': 'sk-cert',
        'ncsc-fi': 'ncsc-fi',
        'govtech csg': 'govtech',
        'document fdn.': 'document foundation',
        'fluid attacks': 'fluid attacks',
        'hidden layer': 'hiddenlayer',
        'ping identity': 'pingidentity',
        'pure storage': 'purestorage',
        'wikimedia-foundation': 'wikimedia foundation',
        'panasonic_holdings_corporation': 'panasonic',
        'zuso art': 'zuso'
    }
    
    if normalized in variations:
        normalized = variations[normalized]
    
    return normalized

def find_matching_cna(cna_name, cnas_list):
    """Find matching CNA in the CNAsList by trying various name matching strategies."""
    normalized_name = normalize_cna_name(cna_name)
    
    for cna in cnas_list:
        # Try exact match on normalized names
        if normalize_cna_name(cna.get('name', '')) == normalized_name:
            return cna
        
        # Try partial match
        cna_normalized = normalize_cna_name(cna.get('name', ''))
        if normalized_name in cna_normalized or cna_normalized in normalized_name:
            return cna
        
        # Check short name if available
        if 'shortName' in cna and normalize_cna_name(cna['shortName']) == normalized_name:
            return cna
    
    return None

def update_cna_files():
    """Update existing CNA JSON files with metadata from CNAsList.json."""
    # Download CNAsList.json
    print("Downloading CNAsList.json...")
    cnas_list = download_cna_list()
    
    if not cnas_list:
        print("Failed to download CNAsList.json")
        return
    
    print(f"Downloaded {len(cnas_list)} CNAs from CNAsList.json")
    
    # Path to CNA data directory
    cna_data_dir = Path("/Users/gamblin/Code/CNAScoreCard/web/cna/data")
    
    if not cna_data_dir.exists():
        print(f"CNA data directory not found: {cna_data_dir}")
        return
    
    updated_count = 0
    not_found = []
    
    # Process each CNA JSON file
    for json_file in cna_data_dir.glob("*.json"):
        try:
            # Load existing CNA data
            with open(json_file, 'r') as f:
                cna_data = json.load(f)
            
            cna_name = cna_data.get('cna_info', {}).get('cna', '')
            if not cna_name:
                continue
            
            # Find matching CNA in CNAsList
            matching_cna = find_matching_cna(cna_name, cnas_list)
            
            if matching_cna:
                # Add metadata to cna_info
                metadata = {
                    'long_name': matching_cna.get('name', ''),
                    'scope': matching_cna.get('scope', []),
                    'contact_email': matching_cna.get('contactEmail', ''),
                    'website': matching_cna.get('website', ''),
                    'advisory_links': [],
                    'participation_level': matching_cna.get('participationLevel', ''),
                    'organization_type': matching_cna.get('organizationType', ''),
                    'geographic_scope': matching_cna.get('geographicScope', []),
                    'industry_sector': matching_cna.get('industrySector', [])
                }
                
                # Extract advisory/security links from website if available
                if metadata['website']:
                    # Common security advisory URL patterns
                    base_url = metadata['website'].rstrip('/')
                    security_paths = [
                        '/security',
                        '/security-advisories',
                        '/advisories',
                        '/security/advisories',
                        '/support/security',
                        '/security-center',
                        '/vulnerabilities'
                    ]
                    
                    for path in security_paths:
                        metadata['advisory_links'].append({
                            'name': 'Security Advisories',
                            'url': base_url + path
                        })
                        break  # Only add one advisory link per CNA
                
                # Update cna_info with metadata
                cna_data['cna_info'].update(metadata)
                
                # Write updated data back to file
                with open(json_file, 'w') as f:
                    json.dump(cna_data, f, indent=2)
                
                updated_count += 1
                print(f"Updated {cna_name} with metadata")
            else:
                not_found.append(cna_name)
                print(f"No match found for {cna_name}")
        
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
    
    print(f"\nUpdated {updated_count} CNA files")
    if not_found:
        print(f"Could not find matches for: {', '.join(not_found)}")

if __name__ == "__main__":
    update_cna_files()