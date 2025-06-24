#!/usr/bin/env python3
"""
Generate individual CNA pages with their last 100 CVEs
"""

import json
import os
from datetime import datetime
from pathlib import Path
import shutil

def load_cve_data():
    """Load CVE data from the JSON file"""
    try:
        with open('data/cve_data.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("CVE data file not found. Please run fetch_cve_data.py first.")
        return []

def get_cnas_with_cves(cve_data):
    """Get all CNAs and their CVEs"""
    cna_cves = {}
    
    for cve in cve_data:
        cna = cve.get('cna', 'Unknown')
        if cna not in cna_cves:
            cna_cves[cna] = []
        cna_cves[cna].append(cve)
    
    # Sort CVEs by date (newest first) and limit to 100
    for cna in cna_cves:
        cna_cves[cna] = sorted(
            cna_cves[cna], 
            key=lambda x: x.get('published_date', ''), 
            reverse=True
        )[:100]
    
    return cna_cves

def generate_cna_page(cna, cves, output_dir):
    """Generate HTML page for a specific CNA"""
    # Clean CNA name for filename
    safe_cna_name = "".join(c for c in cna if c.isalnum() or c in (' ', '-', '_')).rstrip()
    filename = f"{safe_cna_name.replace(' ', '_')}.html"
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cna} - CNA Score Card</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="../style.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <li class="breadcrumb-item"><a href="../index.html">Home</a></li>
                        <li class="breadcrumb-item active" aria-current="page">{cna}</li>
                    </ol>
                </nav>
                
                <h1 class="mb-4">{cna}</h1>
                <p class="lead">Last {len(cves)} CVEs published by {cna}</p>
                
                <div class="row">
"""

    # Add CVE cards
    for cve in cves:
        base_score = cve.get('base_score', 'N/A')
        severity = cve.get('severity', 'Unknown')
        
        # Determine card color based on severity
        card_class = "border-secondary"
        if severity.lower() == "critical":
            card_class = "border-danger"
        elif severity.lower() == "high":
            card_class = "border-warning"
        elif severity.lower() == "medium":
            card_class = "border-info"
        elif severity.lower() == "low":
            card_class = "border-success"
        
        html_content += f"""
                    <div class="col-md-6 col-lg-4 mb-3">
                        <div class="card {card_class}">
                            <div class="card-body">
                                <h6 class="card-title">
                                    <a href="https://www.cve.org/CVERecord?id={cve.get('cve_id', '')}" 
                                       target="_blank" class="text-decoration-none">
                                        {cve.get('cve_id', 'N/A')}
                                    </a>
                                </h6>
                                <div class="row">
                                    <div class="col-6">
                                        <small class="text-muted">Base Score</small>
                                        <div class="fw-bold">{base_score}</div>
                                    </div>
                                    <div class="col-6">
                                        <small class="text-muted">Severity</small>
                                        <div class="fw-bold text-{severity.lower() if severity.lower() in ['critical', 'high', 'medium', 'low'] else 'secondary'}">{severity}</div>
                                    </div>
                                </div>
                                <div class="row mt-2">
                                    <div class="col-6">
                                        <small class="text-muted">Exploitability</small>
                                        <div class="fw-bold">{cve.get('exploitability_score', 'N/A')}</div>
                                    </div>
                                    <div class="col-6">
                                        <small class="text-muted">Impact</small>
                                        <div class="fw-bold">{cve.get('impact_score', 'N/A')}</div>
                                    </div>
                                </div>
                                <div class="mt-2">
                                    <small class="text-muted">Published</small>
                                    <div class="small">{cve.get('published_date', 'N/A')}</div>
                                </div>
                            </div>
                        </div>
                    </div>
"""

    html_content += """
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""

    # Write the HTML file
    output_path = output_dir / filename
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename

def generate_cna_data_files(cna_cves, data_dir):
    """Generate individual JSON data files for each CNA"""
    for cna, cves in cna_cves.items():
        safe_cna_name = "".join(c for c in cna if c.isalnum() or c in (' ', '-', '_')).rstrip()
        filename = f"{safe_cna_name.replace(' ', '_')}.json"
        
        data_file = data_dir / filename
        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump({
                'cna': cna,
                'cve_count': len(cves),
                'last_updated': datetime.now().isoformat(),
                'cves': cves
            }, f, indent=2)

def main():
    print("Generating individual CNA pages...")
    
    # Load CVE data
    cve_data = load_cve_data()
    if not cve_data:
        return
    
    # Create output directories
    web_dir = Path('web')
    cna_dir = web_dir / 'cna'
    cna_data_dir = cna_dir / 'data'
    
    cna_dir.mkdir(parents=True, exist_ok=True)
    cna_data_dir.mkdir(parents=True, exist_ok=True)
    
    # Get CNAs and their CVEs
    cna_cves = get_cnas_with_cves(cve_data)
    
    print(f"Found {len(cna_cves)} CNAs")
    
    # Generate individual CNA pages
    generated_files = []
    for cna, cves in cna_cves.items():
        if cves:  # Only generate pages for CNAs with CVEs
            filename = generate_cna_page(cna, cves, cna_dir)
            generated_files.append((cna, filename, len(cves)))
            print(f"Generated page for {cna}: {len(cves)} CVEs")
    
    # Generate CNA data files
    generate_cna_data_files(cna_cves, cna_data_dir)
    
    # Generate index file for CNA pages
    generate_cna_index(generated_files, cna_dir)
    
    print(f"Generated {len(generated_files)} CNA pages in {cna_dir}")

def generate_cna_index(generated_files, output_dir):
    """Generate an index page listing all CNAs"""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CNAs - CNA Score Card</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="../style.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <li class="breadcrumb-item"><a href="../index.html">Home</a></li>
                        <li class="breadcrumb-item active" aria-current="page">CNAs</li>
                    </ol>
                </nav>
                
                <h1 class="mb-4">CNA Directory</h1>
                <p class="lead">Browse individual CNA pages</p>
                
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>CNA Name</th>
                                <th>CVE Count</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
"""
    
    # Sort CNAs by CVE count (descending)
    sorted_files = sorted(generated_files, key=lambda x: x[2], reverse=True)
    
    for cna, filename, cve_count in sorted_files:
        html_content += f"""
                            <tr>
                                <td>{cna}</td>
                                <td>{cve_count}</td>
                                <td><a href="{filename}" class="btn btn-sm btn-outline-primary">View CVEs</a></td>
                            </tr>
"""
    
    html_content += """
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""
    
    with open(output_dir / 'index.html', 'w', encoding='utf-8') as f:
        f.write(html_content)

if __name__ == "__main__":
    main()