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


def generate_cna_page(cna_name, safe_filename, cna_dir):
    """Generate an individual HTML page for a CNA."""
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cna_name} - CNA ScoreCard</title>
    <link rel="stylesheet" href="../styles.css">
    <link rel="stylesheet" href="cna-styles.css">
</head>
<body>
    <div class="container">
        <div class="breadcrumb">
            <a href="../index.html">← Back to All CNAs</a>
        </div>
        
        <div id="cnaHeader">
            <h1 id="cnaTitle">{cna_name}</h1>
            <div id="cnaStats" class="cna-stats">
                <!-- Stats will be loaded dynamically -->
            </div>
        </div>
        
        <div class="filters">
            <input type="text" id="searchInput" placeholder="Search CVEs...">
            <select id="sortSelect">
                <option value="score">Sort by EAS Score</option>
                <option value="cveId">Sort by CVE ID</option>
                <option value="date">Sort by Date</option>
            </select>
        </div>
        
        <div id="loading">Loading CVE data...</div>
        <div id="cveCards" class="cve-cards"></div>
    </div>
    
    <script>
        const CNA_NAME = "{cna_name}";
        const SAFE_FILENAME = "{safe_filename}";
    </script>
    <script src="cna-script.js"></script>
</body>
</html>'''
    
    # Write the HTML file
    with open(cna_dir / f"{safe_filename}.html", "w") as f:
        f.write(html_content)


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
            cna_info = {
                'cna': cna_name,
                'total_cves_scored': len(cna_cves),
                'average_eas_score': sum(c.get('totalEasScore', 0) for c in cna_cves) / len(cna_cves) if cna_cves else 0,
                'percentile': 0,
                'average_foundational_completeness': sum(c.get('scoreBreakdown', {}).get('foundationalCompleteness', 0) for c in cna_cves) / len(cna_cves) if cna_cves else 0,
                'average_root_cause_analysis': sum(c.get('scoreBreakdown', {}).get('rootCauseAnalysis', 0) for c in cna_cves) / len(cna_cves) if cna_cves else 0,
                'average_severity_context': sum(c.get('scoreBreakdown', {}).get('severityAndImpactContext', 0) for c in cna_cves) / len(cna_cves) if cna_cves else 0,
                'average_actionable_intelligence': sum(c.get('scoreBreakdown', {}).get('actionableIntelligence', 0) for c in cna_cves) / len(cna_cves) if cna_cves else 0,
                'average_data_format_precision': sum(c.get('scoreBreakdown', {}).get('dataFormatAndPrecision', 0) for c in cna_cves) / len(cna_cves) if cna_cves else 0
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
            
            # Generate HTML page for this CNA
            generate_cna_page(cna_name, safe_filename, cna_dir)
            cna_pages_generated += 1
    
    print(f"Generated individual pages for {cna_pages_generated} CNAs")
    
    print("Static data generation complete!")
    print(f"- CNAs: {len(cna_array)}")
    print(f"- Top 100 CVEs: {len(top_100)}") 
    print(f"- Bottom 100 CVEs: {len(bottom_100)}")
    print(f"- Individual CNA pages: {cna_pages_generated}")


if __name__ == "__main__":
    main()