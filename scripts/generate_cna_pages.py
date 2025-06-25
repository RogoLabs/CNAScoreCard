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
    """Load CVE data from the generated JSON files"""
    try:
        # Try to load the top CVEs data first
        with open('web/data/top100_cves.json', 'r') as f:
            top_cves = json.load(f)
        
        with open('web/data/bottom100_cves.json', 'r') as f:
            bottom_cves = json.load(f)
        
        # Combine for processing - these should already have the correct EAS structure
        return top_cves + bottom_cves
    except FileNotFoundError:
        print("CVE data files not found. Please run cnascorecard/generate_static_data.py first.")
        return []

def get_cnas_with_cves(cve_data):
    """Get all CNAs and their CVEs"""
    cna_cves = {}
    
    for cve in cve_data:
        cna = cve.get('assigningCna', 'Unknown')
        if cna not in cna_cves:
            cna_cves[cna] = []
        cna_cves[cna].append(cve)
    
    # Sort CVEs by totalEasScore (highest first) and limit to 100
    for cna in cna_cves:
        cna_cves[cna] = sorted(
            cna_cves[cna], 
            key=lambda x: x.get('totalEasScore', 0), 
            reverse=True
        )[:100]
    
    return cna_cves

# Remove the duplicate scoring functions since we're using EAS data directly

def calculate_cve_score(cve):
    """Calculate individual CVE score based on EAS methodology"""
    # Use the EAS score if available, otherwise return 0
    return cve.get('totalEasScore', 0)

def generate_cna_page(cna, cves, output_dir):
    """Generate HTML page for a specific CNA by copying and modifying the template"""
    # Clean CNA name for filename
    safe_cna_name = "".join(c for c in cna if c.isalnum() or c in (' ', '-', '_')).rstrip()
    filename = f"{safe_cna_name.replace(' ', '_')}.html"
    
    # Read the template HTML file directly
    template_path = Path('web/cna/cna-detail.html')
    if not template_path.exists():
        print(f"Warning: Template file {template_path} not found, using fallback HTML")
        return generate_fallback_cna_page(cna, cves, output_dir, filename)
    
    # Simply copy the template file to the new location with minimal modifications
    with open(template_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Only update the title and CNA-specific variables
    html_content = html_content.replace(
        '<title>CNA Detail - CNA ScoreCard</title>',
        f'<title>{cna} - CNA ScoreCard</title>'
    )
    
    # Update the script section to include the specific CNA name
    script_replacement = f"""    <script>
        // Define CNA_NAME and SAFE_FILENAME for the script
        const CNA_NAME = '{cna.replace("'", "\\'")}';
        const SAFE_FILENAME = '{safe_cna_name.replace(" ", "_")}';
    </script>"""
    
    html_content = html_content.replace(
        '    <script>\n        // Define CNA_NAME and SAFE_FILENAME for the script\n        const CNA_NAME = new URLSearchParams(window.location.search).get(\'cna\') || \'adobe\';\n        const SAFE_FILENAME = CNA_NAME.replace(/[^a-zA-Z0-9\\s\\-_]/g, \'\').trim().replace(/\\s+/g, \'_\');\n    </script>',
        script_replacement
    )
    
    # Write the HTML file
    output_path = output_dir / filename
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return filename

def generate_fallback_cna_page(cna, cves, output_dir, filename):
    """Fallback HTML generation if template file is not found"""
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cna} - CNA ScoreCard</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <nav class="breadcrumb">
            <a href="index.html">← Back to Home</a>
        </nav>
        
        <div id="loading">Loading CNA data...</div>
        
        <div id="cnaHeader" class="cna-header" style="display: none;">
            <h1 id="cnaTitle">{cna}</h1>
            <div id="cnaStats"></div>
        </div>
        
        <div class="section-header" id="cveSection" style="display: none;">
            <h2>Recent CVE Scores</h2>
            <div class="controls">
                <input type="text" id="searchInput" placeholder="Search CVEs...">
                <select id="sortSelect">
                    <option value="score">Sort by EAS Score</option>
                    <option value="cveId">Sort by CVE ID</option>
                </select>
            </div>
        </div>
        
        <div id="cveCards" class="cve-cards"></div>
    </div>
    
    <script>
        const CNA_NAME = '{cna.replace("'", "\\'")}';
        const SAFE_FILENAME = '{cna.replace(" ", "_")}';
    </script>
    <script src="cna-script.js"></script>
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
        
        # Calculate CNA info from CVEs
        if cves:
            total_cves = len(cves)
            avg_total_eas = sum(c.get('totalEasScore', 0) for c in cves) / total_cves
            avg_foundational = sum(c.get('scoreBreakdown', {}).get('foundationalCompleteness', 0) for c in cves) / total_cves
            avg_root_cause = sum(c.get('scoreBreakdown', {}).get('rootCauseAnalysis', 0) for c in cves) / total_cves
            avg_cpe_identifier = sum(c.get('scoreBreakdown', {}).get('cpeIdentifier', 0) for c in cves) / total_cves
            avg_severity = sum(c.get('scoreBreakdown', {}).get('severityAndImpactContext', 0) for c in cves) / total_cves
            avg_actionable = sum(c.get('scoreBreakdown', {}).get('actionableIntelligence', 0) for c in cves) / total_cves
            avg_format = sum(c.get('scoreBreakdown', {}).get('dataFormatAndPrecision', 0) for c in cves) / total_cves
            
            cna_info = {
                'cna': cna,
                'total_cves_scored': total_cves,
                'average_eas_score': round(avg_total_eas, 2),
                'average_foundational_completeness': round(avg_foundational, 2),
                'average_root_cause_analysis': round(avg_root_cause, 2),
                'average_cpe_identifier': round(avg_cpe_identifier, 2),
                'average_severity_context': round(avg_severity, 2),
                'average_actionable_intelligence': round(avg_actionable, 2),
                'average_data_format_precision': round(avg_format, 2),
                'percentile': 50.0  # Placeholder - would need all CNAs to calculate real percentile
            }
        else:
            cna_info = {
                'cna': cna,
                'total_cves_scored': 0,
                'average_eas_score': 0,
                'average_foundational_completeness': 0,
                'average_root_cause_analysis': 0,
                'average_cpe_identifier': 0,
                'average_severity_context': 0,
                'average_actionable_intelligence': 0,
                'average_data_format_precision': 0,
                'percentile': 0
            }
        
        data_file = data_dir / filename
        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump({
                'cna_info': cna_info,
                'recent_cves': cves,
                'total_cves': len(cves)
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