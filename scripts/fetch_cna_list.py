#!/usr/bin/env python3
"""
Script to download and parse CNAsList.json from the CVE Project website
and create a lookup file for CNA details.
"""

import json
import requests
import os
from pathlib import Path

def fetch_cna_list():
    """Download CNAsList.json from the CVE Project website"""
    url = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching CNAsList.json: {e}")
        return None

def process_cna_data(cna_list):
    """Process the CNA list into a lookup dictionary"""
    cna_lookup = {}
    
    for cna in cna_list:
        # Extract the CNA short name/ID for lookup
        cna_id = cna.get('shortName', '').strip()
        if not cna_id:
            continue
            
        # Clean up the data
        processed_cna = {
            'shortName': cna.get('shortName', ''),
            'name': cna.get('name', ''),
            'scope': cna.get('scope', ''),
            'contactEmail': cna.get('contactEmail', ''),
            'website': cna.get('website', ''),
            'advisory': cna.get('advisory', ''),
            'region': cna.get('region', ''),
            'country': cna.get('country', ''),
            'type': cna.get('type', ''),
            'dateAssigned': cna.get('dateAssigned', ''),
            'parentCNA': cna.get('parentCNA', ''),
            'rootCNA': cna.get('rootCNA', '')
        }
        
        # Remove empty fields
        processed_cna = {k: v for k, v in processed_cna.items() if v}
        
        cna_lookup[cna_id.lower()] = processed_cna
    
    return cna_lookup

def main():
    """Main function to fetch and process CNA data"""
    print("Fetching CNAsList.json...")
    cna_list = fetch_cna_list()
    
    if not cna_list:
        print("Failed to fetch CNA list")
        return
    
    print(f"Processing {len(cna_list)} CNAs...")
    cna_lookup = process_cna_data(cna_list)
    
    # Create output directory if it doesn't exist
    output_dir = Path(__file__).parent.parent / "web" / "cna" / "data"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save the lookup data
    output_file = output_dir / "cna_details.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(cna_lookup, f, indent=2, ensure_ascii=False)
    
    print(f"CNA details saved to {output_file}")
    print(f"Processed {len(cna_lookup)} CNAs successfully")

if __name__ == "__main__":
    main()