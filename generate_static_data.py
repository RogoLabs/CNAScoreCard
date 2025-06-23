#!/usr/bin/env python3
"""
Static data generation script for CNA ScoreCard.
Generates JSON files for the static website.
"""

import json
import os
from pathlib import Path
from cnascorecard.main import generate_reports


def main():
    """Generate static data files for the website."""
    print("Generating CNA and CVE reports...")
    
    # Generate the reports
    cna_data, cve_data = generate_reports()
    
    # Create output directories
    output_dir = Path("web/output")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Saving CNA data ({len(cna_data)} CNAs)...")
    # Save complete CNA report data
    with open(output_dir / "cnas.json", "w") as f:
        json.dump(cna_data, f, indent=2)
    
    print(f"Processing CVE data ({len(cve_data)} CVEs)...")
    # Sort CVEs by score (assuming score is a numeric field)
    sorted_cves = sorted(cve_data, key=lambda x: x.get('score', 0), reverse=True)
    
    # Save top 100 CVEs
    top_100 = sorted_cves[:100]
    with open(output_dir / "top100_cves.json", "w") as f:
        json.dump(top_100, f, indent=2)
    
    # Save bottom 100 CVEs
    bottom_100 = sorted_cves[-100:]
    with open(output_dir / "bottom100_cves.json", "w") as f:
        json.dump(bottom_100, f, indent=2)
    
    print("Static data generation complete!")
    print(f"- CNAs: {len(cna_data)}")
    print(f"- Top 100 CVEs: {len(top_100)}")
    print(f"- Bottom 100 CVEs: {len(bottom_100)}")


if __name__ == "__main__":
    main()