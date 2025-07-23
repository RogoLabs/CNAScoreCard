#!/usr/bin/env python3
"""
Fix CNA Types Helper Script

This script downloads the authoritative CNA list from GitHub and uses it to update
the cnaTypes field in our combined JSON with the correct type information.
"""

import json
import os
import sys
import requests
from pathlib import Path

# Configuration
GITHUB_CNA_LIST_URL = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"
COMBINED_JSON_PATH = "web/data/cna_combined.json"

def download_cna_list():
    """Download the authoritative CNA list from GitHub"""
    try:
        print(f"Downloading CNA list from {GITHUB_CNA_LIST_URL}...")
        response = requests.get(GITHUB_CNA_LIST_URL)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        cna_list = response.json()
        print(f"Successfully downloaded CNA list with {len(cna_list)} entries")
        return cna_list
    except Exception as e:
        print(f"Error downloading CNA list: {e}", file=sys.stderr)
        return None

def build_cna_type_map(cna_list):
    """Build a mapping of CNA short names to their types"""
    cna_type_map = {}
    
    for cna in cna_list:
        short_name = cna.get("shortName", "").strip().lower()
        org_name = cna.get("organizationName", "").strip().lower()
        
        # Extract type information from the CNA list
        # Note: The GitHub data doesn't seem to have type info directly,
        # but we can infer some types from organization name or other fields
        cna_type = None
        
        # Try to determine the CNA type based on the organization name or other attributes
        if "cert" in short_name or "cert" in org_name:
            cna_type = "CERT"
        elif "security" in short_name or "security" in org_name:
            cna_type = "Vendor"
        elif "project" in short_name or "project" in org_name:
            cna_type = "Open Source"
        elif "foundation" in short_name or "foundation" in org_name:
            cna_type = "Open Source"
        elif "bounty" in short_name or "bounty" in org_name:
            cna_type = "Bug Bounty Provider"
        else:
            # Default to Vendor if we can't determine the type
            cna_type = "Vendor"
        
        if short_name:
            cna_type_map[short_name] = cna_type
    
    print(f"Created CNA type map with {len(cna_type_map)} entries")
    return cna_type_map

def update_combined_json(cna_type_map):
    """Update the combined JSON with the correct CNA types"""
    try:
        # Load the combined JSON
        with open(COMBINED_JSON_PATH, 'r') as f:
            combined_data = json.load(f)
        
        fixed_count = 0
        missing_types = []
        for cna in combined_data:
            short_name = cna.get("shortName", "").lower()
            
            # Check if this CNA has empty, missing, or 'Unknown' types
            # The empty array check needs to explicitly look at the JSON structure
            cna_types = cna.get("cnaTypes", [])
            if (not cna_types or 
                (isinstance(cna_types, list) and len(cna_types) == 0) or
                (isinstance(cna_types, list) and len(cna_types) == 1 and cna_types[0] == "Unknown") or
                cna.get("cnaType") == "Unknown"):
                # Try to find the type in our map
                if short_name in cna_type_map:
                    cna_type = cna_type_map[short_name]
                    cna["cnaTypes"] = [cna_type]
                    cna["cnaType"] = cna_type
                    fixed_count += 1
                    missing_types.append(short_name)
                else:
                    # Default to "Vendor" if not found
                    cna["cnaTypes"] = ["Vendor"]
                    cna["cnaType"] = "Vendor"
                    fixed_count += 1
                    missing_types.append(short_name)
        
        # Save the updated combined JSON
        with open(COMBINED_JSON_PATH, 'w') as f:
            json.dump(combined_data, f, indent=2)
        
        print(f"Updated {fixed_count} CNAs with missing type information")
        if missing_types:
            print(f"Fixed types for: {', '.join(missing_types[:10])}")
            if len(missing_types) > 10:
                print(f"...and {len(missing_types) - 10} more")
        return fixed_count
    except Exception as e:
        print(f"Error updating combined JSON: {e}", file=sys.stderr)
        return 0

def main():
    """Main function"""
    # Ensure the combined JSON exists
    if not os.path.exists(COMBINED_JSON_PATH):
        print(f"Error: Combined JSON file not found at {COMBINED_JSON_PATH}", file=sys.stderr)
        return 1
    
    # Download the CNA list
    cna_list = download_cna_list()
    if not cna_list:
        return 1
    
    # Build the CNA type map
    cna_type_map = build_cna_type_map(cna_list)
    
    # Update the combined JSON
    fixed_count = update_combined_json(cna_type_map)
    
    print(f"CNA types fixed: {fixed_count}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
