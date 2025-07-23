#!/usr/bin/env python3

import json
import os
import glob
from pathlib import Path

def generate_combined_cna_json():
    """
    Generate a combined JSON file for the CNA index page table.
    
    This script extracts data from individual CNA JSON files and combines it into
    a single JSON file with all the necessary metrics for the table display.
    
    Fields included:
    - Ranking (from new tie-based ranking system)
    - CNA Name (short name and full organization name)
    - CNA Type
    - CVE Count
    - Scoring metrics (foundational completeness, root cause analysis, etc.)
    - Trend information
    """
    print("Generating combined CNA JSON for index page table...")
    
    # Paths
    base_path = Path(__file__).resolve().parent
    cna_data_path = base_path / 'web' / 'data' / 'cna'
    output_path = base_path / 'web' / 'data' / 'cna_combined.json'
    
    # Verify paths
    if not cna_data_path.exists():
        raise FileNotFoundError(f"CNA data directory not found: {cna_data_path}")
    
    # Find all CNA JSON files
    cna_files = list(cna_data_path.glob('*.json'))
    print(f"Found {len(cna_files)} CNA JSON files")
    
    combined_data = []
    
    # Process each CNA JSON file
    for cna_file in cna_files:
        try:
            with open(cna_file, 'r') as f:
                cna_data = json.load(f)
            
            # Extract CNA info
            cna_info = cna_data.get('cna_info', {})
            short_name = cna_info.get('cna', cna_file.stem)
            org_name = cna_info.get('organizationName', short_name)
            
            # Extract CNA types (keep the full array)
            cna_types = cna_info.get('cnaTypes', [])
            if not cna_types:
                cna_types = ["Unknown"]
            # Preserve backwards compatibility with a single string for old code
            cna_type = cna_types[0]
            
            # Extract ranking info
            rank = cna_data.get('rank', 0)
            active_cna_count = cna_data.get('active_cna_count', 0)
            percentile = cna_data.get('percentile', 0)
            
            # Extract CVE counts
            total_cves = cna_info.get('total_cves', 0)
            recent_cves = len(cna_data.get('recent_cves', []))
            
            # Extract scoring metrics
            cna_scoring = cna_data.get('cna_scoring', [{}])[0] if cna_data.get('cna_scoring') else {}
            
            # Create the combined entry
            entry = {
                "shortName": short_name,
                "organizationName": org_name,
                "cnaType": cna_type,
                "cnaTypes": cna_types,
                "rank": rank,
                "active_cna_count": active_cna_count,
                "percentile": percentile,
                "total_cves": total_cves,
                "recent_cves": recent_cves,
                "scores": {
                    "overall_average_score": cna_scoring.get('overall_average_score', 0),
                    "foundational_completeness": cna_scoring.get('percent_foundational_completeness', 0),
                    "root_cause_analysis": cna_scoring.get('percent_root_cause_analysis', 0),
                    "software_identification": cna_scoring.get('percent_software_identification', 0),
                    "severity_and_impact": cna_scoring.get('percent_severity_and_impact', 0),
                    "patchinfo": cna_scoring.get('percent_patchinfo', 0)
                },
                "trend": {
                    "direction": cna_data.get('trend_direction', 'steady'),
                    "description": cna_data.get('trend_description', '➡️ No change'),
                    "monthly_data": cna_scoring.get('monthly_trends', [0] * 6)
                }
            }
            
            combined_data.append(entry)
            
        except Exception as e:
            print(f"Error processing {cna_file.name}: {e}")
    
    # Sort the combined data by rank (ascending)
    combined_data.sort(key=lambda x: x['rank'])
    
    # Write the combined data to file
    with open(output_path, 'w') as f:
        json.dump(combined_data, f, indent=2)
    
    print(f"Successfully generated combined CNA data with {len(combined_data)} entries")
    print(f"Output saved to: {output_path}")
    
    return combined_data

if __name__ == "__main__":
    generate_combined_cna_json()
