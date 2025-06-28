#!/usr/bin/env python3
"""
Static data generation script for CNA ScoreCard.
Generates JSON files for the static website.
"""

import json
import os
from pathlib import Path
import sys

# Add the parent directory to the Python path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cnascorecard.main import generate_reports





def main():
    """Generate static data files for the website."""
    print("Generating CNA and CVE reports...")
    
    # Generate the reports
    cna_data, cve_data = generate_reports()
    
    # Create output directories
    output_dir = Path("web/data")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Saving CNA data ({len(cna_data)} CNAs)...")
    # Ensure CNA data is in the correct format (array)
    if isinstance(cna_data, dict):
        # If it's a dict, convert to array of values
        cna_array = list(cna_data.values())
    elif isinstance(cna_data, list):
        cna_array = cna_data
    else:
        raise ValueError(f"Unexpected CNA data type: {type(cna_data)}")
    
    # Save complete CNA report data
    with open(output_dir / "cnas.json", "w") as f:
        json.dump(cna_array, f, indent=2)
    
    print(f"Processing CVE data ({len(cve_data)} CVEs)...")
    # Sort CVEs by totalEasScore (EAS scoring system)
    sorted_cves = sorted(cve_data, key=lambda x: x.get('totalEasScore', 0), reverse=True)
    
    # Save top 100 CVEs
    top_100 = sorted_cves[:100]
    with open(output_dir / "top100_cves.json", "w") as f:
        json.dump(top_100, f, indent=2)
    
    # Save bottom 100 CVEs
    bottom_100 = sorted_cves[-100:]
    with open(output_dir / "bottom100_cves.json", "w") as f:
        json.dump(bottom_100, f, indent=2)
    
    # Create CNA-specific data
    print("Generating individual CNA data files...")
    cna_dir = Path("web/cna")
    cna_data_dir = cna_dir / "data"
    cna_data_dir.mkdir(parents=True, exist_ok=True)
    
    # Group CVEs by CNA
    cves_by_cna = {}
    for cve in cve_data:
        cna_name = cve.get('assigningCna', 'Unknown')
        if cna_name not in cves_by_cna:
            cves_by_cna[cna_name] = []
        cves_by_cna[cna_name].append(cve)
    
    # Generate individual CNA pages and data
    cna_pages_generated = 0
    for cna_name, cna_cves in cves_by_cna.items():
        # Sort CVEs by score (highest first)
        sorted_cna_cves = sorted(cna_cves, key=lambda x: x.get('totalEasScore', 0), reverse=True)
        
        # Take first 100 CVEs (highest scoring ones)
        recent_cves = sorted_cna_cves[:100]
        
        # Find CNA info from the main CNA data
        cna_info = None
        for cna in cna_array:
            if cna.get('cna') == cna_name:
                cna_info = cna
                break
        
        if not cna_info:
            # Create basic info for unknown CNAs
            # Helper function to format averages consistently
            def format_avg(values, count):
                if not count:
                    return 0
                avg = sum(values) / count
                rounded = round(avg, 2)
                return int(rounded) if rounded % 1 == 0 else rounded
            
            cna_info = {
                'cna': cna_name,
                'total_cves_scored': len(cna_cves),
                'average_eas_score': format_avg([c.get('totalEasScore', 0) for c in cna_cves], len(cna_cves)),
                'percentile': 0,
                'average_foundational_completeness': format_avg([c.get('scoreBreakdown', {}).get('foundationalCompleteness', 0) for c in cna_cves], len(cna_cves)),
                'average_root_cause_analysis': format_avg([c.get('scoreBreakdown', {}).get('rootCauseAnalysis', 0) for c in cna_cves], len(cna_cves)),
                'average_software_identification': format_avg([c.get('scoreBreakdown', {}).get('softwareIdentification', 0) for c in cna_cves], len(cna_cves)),
                'average_severity_context': format_avg([c.get('scoreBreakdown', {}).get('severityAndImpactContext', 0) for c in cna_cves], len(cna_cves)),
                'average_actionable_intelligence': format_avg([c.get('scoreBreakdown', {}).get('actionableIntelligence', 0) for c in cna_cves], len(cna_cves))
            }
        
        # Only generate pages for CNAs with CVEs
        if len(cna_cves) > 0:
            # Save CNA-specific data
            cna_data_file = {
                'cna_info': cna_info,
                'recent_cves': recent_cves,
                'total_cves': len(cna_cves)
            }
            
            # Create safe filename
            safe_filename = "".join(c for c in cna_name if c.isalnum() or c in (' ', '-', '_')).strip()
            safe_filename = safe_filename.replace(' ', '_')
            
            with open(cna_data_dir / f"{safe_filename}.json", "w") as f:
                json.dump(cna_data_file, f, indent=2)
            
            cna_pages_generated += 1
    
    print(f"Generated individual data files for {cna_pages_generated} CNAs")
    
    print("Static data generation complete!")
    print(f"- CNAs: {len(cna_array)}")
    print(f"- Top 100 CVEs: {len(top_100)}") 
    print(f"- Bottom 100 CVEs: {len(bottom_100)}")
    print(f"- Individual CNA data files: {cna_pages_generated}")


if __name__ == "__main__":
    main()