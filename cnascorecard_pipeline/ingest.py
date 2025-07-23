"""
ingest.py: Load CVE and CNA data from cve_data directory (CVE5 format).
"""
import os
import json
from glob import glob

from datetime import datetime

def load_cve_records(cve_dir="../cve_data", start_date=None, end_date=None):
    """
    Load CVE JSON records from the cve_data directory, optionally filtering by datePublished.
    start_date and end_date should be strings in 'YYYY-MM-DD' format.
    Returns a list of CVE dicts.
    
    Optimized to only load CVE files from recent years (2024-2025) for performance.
    """
    # Only load CVE files from recent years to improve performance
    # Since we typically only need last 6 months, focus on 2024-2025
    recent_years = ['2024', '2025']
    cve_files = []
    
    for year in recent_years:
        year_pattern = os.path.join(cve_dir, "cves", year, "**", "CVE-*.json")
        year_files = glob(year_pattern, recursive=True)
        cve_files.extend(year_files)
        print(f"Found {len(year_files)} CVE files in {year}")
    
    print(f"Total CVE files to process: {len(cve_files)} (optimized from 300k+ total)")
    records = []
    for f in cve_files:
        try:
            with open(f, "r") as fin:
                data = json.load(fin)
                
                # Skip files that don't contain CVE record objects
                if not isinstance(data, dict):
                    continue
                
                # Check if it's a valid CVE record by looking for required fields
                if "cveMetadata" not in data or "cveId" not in data.get("cveMetadata", {}):
                    continue
                
                cve = data
                
                # Filter out rejected CVEs to ensure accurate completeness calculations
                cve_state = cve.get("cveMetadata", {}).get("state")
                if cve_state == "REJECTED":
                    continue
                
                pub_date = cve.get("cveMetadata", {}).get("datePublished")
                if pub_date and (start_date or end_date):
                    pub_dt = datetime.strptime(pub_date[:10], "%Y-%m-%d")
                    if start_date:
                        start_dt = datetime.strptime(start_date, "%Y-%m-%d")
                        if pub_dt < start_dt:
                            continue
                    if end_date:
                        end_dt = datetime.strptime(end_date, "%Y-%m-%d")
                        if pub_dt > end_dt:
                            continue
                records.append(cve)
        except Exception as e:
            # Skip files that can't be loaded or parsed
            continue
    return records

def load_cna_list(cve_records):
    """
    Extract unique CNA shortNames from CVE records.
    Returns a list of CNA dicts.
    """
    cna_set = set()
    for cve in cve_records:
        containers = cve.get("containers", {})
        cna = containers.get("cna", {})
        provider = cna.get("providerMetadata", {})
        short_name = provider.get("shortName")
        if short_name:
            cna_set.add(short_name)
    return [{"shortName": c} for c in sorted(cna_set)]

if __name__ == "__main__":
    records = load_cve_records()
    print(f"Loaded {len(records)} CVE records.")
    cna_list = load_cna_list(records)
    print(f"Found {len(cna_list)} unique CNAs.")
