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
        
        # Combine for processing
        return top_cves + bottom_cves
    except FileNotFoundError:
        print("CVE data files not found. Please run cnascorecard/generate_static_data.py first.")
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

def calculate_foundational_score(cve):
    """Calculate foundational completeness score for a CVE"""
    score = 0
    if cve.get('vendor') and cve.get('vendor') != 'N/A':
        score += 10
    if cve.get('product') and cve.get('product') != 'N/A':
        score += 10
    if cve.get('description') and len(cve.get('description', '')) > 40:
        score += 10
    return min(score, 30)  # Cap at 30

def calculate_root_cause_score(cve):
    """Calculate root cause analysis score for a CVE"""
    if cve.get('cwe_id'):
        return 20
    return 0

def calculate_severity_score(cve):
    """Calculate severity context score for a CVE"""
    score = 0
    if cve.get('base_score'):
        score += 15
    if cve.get('cvss_vector'):
        score += 10
    return min(score, 25)  # Cap at 25

def calculate_actionable_score(cve):
    """Calculate actionable intelligence score for a CVE"""
    score = 0
    references = cve.get('references', [])
    score += min(len(references) * 3, 12)  # Max 12 points for references
    if any('exploit' in ref.get('url', '').lower() for ref in references):
        score += 5
    if cve.get('vex_data'):
        score += 3
    return min(score, 20)  # Cap at 20

def calculate_format_score(cve):
    """Calculate data format precision score for a CVE"""
    if cve.get('cpe'):
        return 5
    return 0

def calculate_cna_score(cves):
    """Calculate overall CNA score from CVEs"""
    if not cves:
        return 0
    
    total_score = 0
    for cve in cves:
        cve_score = calculate_cve_score(cve)
        total_score += cve_score
    
    return total_score / len(cves)

def calculate_cve_score(cve):
    """Calculate individual CVE score based on EAS methodology"""
    score = 0
    
    # Foundational Completeness (30 points max)
    if cve.get('vendor') and cve.get('vendor') != 'N/A':
        score += 10
    if cve.get('product') and cve.get('product') != 'N/A':
        score += 10
    if cve.get('description') and len(cve.get('description', '')) > 40:
        score += 10
    
    # Root Cause Analysis (20 points max)
    if cve.get('cwe_id'):
        score += 20
    
    # Severity Context (25 points max)
    if cve.get('base_score'):
        score += 15
    if cve.get('cvss_vector'):
        score += 10
    
    # Actionable Intelligence (20 points max)
    references = cve.get('references', [])
    score += min(len(references) * 3, 12)  # Max 12 points for references
    if any('exploit' in ref.get('url', '').lower() for ref in references):
        score += 5
    if cve.get('vex_data'):
        score += 3
    
    # Data Format Precision (5 points max)
    if cve.get('cpe'):
        score += 5
    
    return min(score, 100)  # Cap at 100

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