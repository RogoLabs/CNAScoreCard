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
    return score

def calculate_root_cause_score(cve):
    """Calculate root cause analysis score for a CVE"""
    if cve.get('cwe_id'):
        return 20
    return 0

def calculate_severity_score(cve):
    """Calculate severity context score for a CVE"""
    score = 0
    if cve.get('base_score'):
        score += 10
    if cve.get('cvss_vector'):
        score += 15
    return score

def calculate_actionable_score(cve):
    """Calculate actionable intelligence score for a CVE"""
    score = 0
    references = cve.get('references', [])
    score += min(len(references) * 4, 12)  # Max 12 points for references
    if any('exploit' in ref.get('url', '').lower() for ref in references):
        score += 5
    if cve.get('vex_data'):
        score += 3
    return score

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
    
    # Foundational Completeness (30 points)
    if cve.get('vendor') and cve.get('vendor') != 'N/A':
        score += 10
    if cve.get('product') and cve.get('product') != 'N/A':
        score += 10
    if cve.get('description') and len(cve.get('description', '')) > 40:
        score += 10
    
    # Root Cause Analysis (20 points)
    if cve.get('cwe_id'):
        score += 20
    
    # Severity Context (25 points)
    if cve.get('base_score'):
        score += 10
    if cve.get('cvss_vector'):
        score += 15
    
    # Actionable Intelligence (20 points)
    references = cve.get('references', [])
    score += min(len(references) * 4, 12)  # Max 12 points for references
    if any('exploit' in ref.get('url', '').lower() for ref in references):
        score += 5
    if cve.get('vex_data'):
        score += 3
    
    # Data Format Precision (5 points)
    if cve.get('cpe'):
        score += 5
    
    return min(score, 100)  # Cap at 100

def generate_cna_page(cna, cves, output_dir):
    """Generate HTML page for a specific CNA"""
    # Clean CNA name for filename
    safe_cna_name = "".join(c for c in cna if c.isalnum() or c in (' ', '-', '_')).rstrip()
    filename = f"{safe_cna_name.replace(' ', '_')}.html"
    
    # Calculate CNA metrics
    cna_score = calculate_cna_score(cves)
    
    # Calculate average scores by category
    foundational_avg = sum(min(30, calculate_foundational_score(cve)) for cve in cves) / len(cves) if cves else 0
    root_cause_avg = sum(min(20, calculate_root_cause_score(cve)) for cve in cves) / len(cves) if cves else 0
    severity_avg = sum(min(25, calculate_severity_score(cve)) for cve in cves) / len(cves) if cves else 0
    actionable_avg = sum(min(20, calculate_actionable_score(cve)) for cve in cves) / len(cves) if cves else 0
    format_avg = sum(min(5, calculate_format_score(cve)) for cve in cves) / len(cves) if cves else 0
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cna} - CNA ScoreCard</title>
    <link rel="stylesheet" href="../styles.css">
    <style>
        .cna-header {{
            background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%);
            color: white;
            padding: 3rem 0;
            margin-bottom: 2rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .cna-header-content {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 2rem;
            gap: 2rem;
        }}
        
        .cna-info h1 {{
            font-size: 2.5rem;
            margin-bottom: 1rem;
            font-weight: 700;
            color: white;
        }}
        
        .cna-stats {{
            display: flex;
            gap: 2rem;
            margin-top: 1rem;
        }}
        
        .stat {{
            display: flex;
            flex-direction: column;
        }}
        
        .stat-label {{
            font-size: 0.9rem;
            opacity: 0.8;
            color: rgba(255,255,255,0.8);
        }}
        
        .stat-value {{
            font-size: 1.2rem;
            font-weight: 600;
            color: white;
        }}
        
        .cna-score-display {{
            text-align: center;
            background: rgba(255, 255, 255, 0.1);
            padding: 1.5rem;
            border-radius: 12px;
            backdrop-filter: blur(10px);
            min-width: 200px;
        }}
        
        .main-score {{
            font-size: 3rem;
            font-weight: 700;
            line-height: 1;
            color: white;
        }}
        
        .score-label {{
            font-size: 1rem;
            margin: 0.5rem 0;
            opacity: 0.9;
            color: rgba(255,255,255,0.9);
        }}
        
        .score-breakdown {{
            background: rgba(255, 255, 255, 0.1);
            padding: 1.5rem;
            border-radius: 12px;
            backdrop-filter: blur(10px);
        }}
        
        .score-breakdown h3 {{
            margin-bottom: 1rem;
            font-size: 1.2rem;
            color: white;
        }}
        
        .breakdown-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        
        .breakdown-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            color: white;
        }}
        
        .breakdown-item:last-child {{
            border-bottom: none;
        }}
        
        .category {{
            font-size: 0.9rem;
            color: rgba(255,255,255,0.9);
        }}
        
        .breakdown-item .score {{
            font-weight: 600;
            color: white;
        }}
        
        .cve-section {{
            margin-top: 2rem;
        }}
        
        .section-header {{
            margin: 2rem 0 1rem 0;
            padding-bottom: 1rem;
            border-bottom: 2px solid #e9ecef;
        }}
        
        .section-header h2 {{
            margin: 0 0 1rem 0;
            color: #2c3e50;
            font-size: 1.5rem;
        }}
        
        .controls {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        
        .controls input, .controls select {{
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 0.9rem;
        }}
        
        .cve-card {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #e0e0e0;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }}
        
        .cve-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }}
        
        .cve-card[data-score-range="high"] {{
            border-left-color: #4CAF50;
        }}
        
        .cve-card[data-score-range="medium"] {{
            border-left-color: #FF9800;
        }}
        
        .cve-card[data-score-range="low"] {{
            border-left-color: #f44336;
        }}
        
        .cve-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid #eee;
        }}
        
        .cve-id {{
            font-weight: 600;
            color: #2196F3;
            text-decoration: none;
            font-size: 1.1rem;
        }}
        
        .cve-id:hover {{
            text-decoration: underline;
        }}
        
        .cve-score {{
            font-size: 1.3rem;
            font-weight: 700;
            color: #333;
            background: #f8f9fa;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
        }}
        
        .cve-metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 0.5rem;
        }}
        
        .cve-metrics .metric {{
            display: flex;
            justify-content: space-between;
            padding: 0.25rem 0;
            font-size: 0.9rem;
        }}
        
        .breadcrumb {{
            margin-bottom: 0;
            padding: 1rem 0;
        }}
        
        .breadcrumb a {{
            color: #2196F3;
            text-decoration: none;
        }}
        
        .breadcrumb a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <nav class="breadcrumb">
            <a href="../index.html">← Back to Home</a>
        </nav>
        
        <div class="cna-header">
            <div class="container">
                <div class="cna-header-content">
                    <div class="cna-info">
                        <h1>{cna}</h1>
                        <div class="cna-stats">
                            <div class="stat">
                                <span class="stat-label">Total CVEs:</span>
                                <span class="stat-value">{len(cves)}</span>
                            </div>
                            <div class="stat">
                                <span class="stat-label">Recent CVEs shown:</span>
                                <span class="stat-value">{len(cves)}</span>
                            </div>
                        </div>
                    </div>
                    <div class="cna-score-display">
                        <div class="main-score">{cna_score:.1f}</div>
                        <div class="score-label">CNA Score</div>
                    </div>
                </div>
                
                <div class="score-breakdown">
                    <h3>Average Scores by Category</h3>
                    <div class="breakdown-grid">
                        <div class="breakdown-item">
                            <span class="category">Foundational Completeness</span>
                            <span class="score">{foundational_avg:.1f}/30</span>
                        </div>
                        <div class="breakdown-item">
                            <span class="category">Root Cause Analysis</span>
                            <span class="score">{root_cause_avg:.1f}/20</span>
                        </div>
                        <div class="breakdown-item">
                            <span class="category">Severity Context</span>
                            <span class="score">{severity_avg:.1f}/25</span>
                        </div>
                        <div class="breakdown-item">
                            <span class="category">Actionable Intelligence</span>
                            <span class="score">{actionable_avg:.1f}/20</span>
                        </div>
                        <div class="breakdown-item">
                            <span class="category">Data Format Precision</span>
                            <span class="score">{format_avg:.1f}/5</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="cve-section">
            <div class="section-header">
                <h2>Recent CVE Scores</h2>
                <div class="controls">
                    <input type="text" id="cve-search" placeholder="Search CVEs..." />
                    <select id="cve-sort">
                        <option value="score">Sort by EAS Score</option>
                        <option value="id">Sort by CVE ID</option>
                    </select>
                </div>
            </div>
            
            <div class="cve-container">
"""

    # Add CVE cards
    for cve in cves:
        cve_score = calculate_cve_score(cve)
        
        # Determine score range for color coding
        score_range = 'low'
        if cve_score >= 70:
            score_range = 'high'
        elif cve_score >= 40:
            score_range = 'medium'
        
        # Calculate individual component scores for display
        foundational = calculate_foundational_score(cve)
        root_cause = calculate_root_cause_score(cve)
        severity = calculate_severity_score(cve)
        actionable = calculate_actionable_score(cve)
        format_precision = calculate_format_score(cve)
        
        html_content += f"""
                <div class="cve-card" data-score-range="{score_range}">
                    <div class="cve-header">
                        <a href="https://www.cve.org/CVERecord?id={cve.get('cve_id', '')}" 
                           target="_blank" class="cve-id">
                            {cve.get('cve_id', 'N/A')}
                        </a>
                        <div class="cve-score">{cve_score:.1f}/100</div>
                    </div>
                    <div class="cve-metrics">
                        <div class="metric">
                            <span>Foundational Completeness</span>
                            <span>{foundational:.1f}/30</span>
                        </div>
                        <div class="metric">
                            <span>Root Cause Analysis</span>
                            <span>{root_cause:.1f}/20</span>
                        </div>
                        <div class="metric">
                            <span>Severity Context</span>
                            <span>{severity:.1f}/25</span>
                        </div>
                        <div class="metric">
                            <span>Actionable Intelligence</span>
                            <span>{actionable:.1f}/20</span>
                        </div>
                        <div class="metric">
                            <span>Data Format Precision</span>
                            <span>{format_precision:.1f}/5</span>
                        </div>
                    </div>
                </div>
"""

    html_content += """
            </div>
        </div>
    </div>
    
    <script>
        // Add search functionality
        document.getElementById('cve-search').addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();
            const cveCards = document.querySelectorAll('.cve-card');
            
            cveCards.forEach(card => {
                const cveId = card.querySelector('.cve-id').textContent.toLowerCase();
                if (cveId.includes(searchTerm)) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        });
        
        // Add sort functionality
        document.getElementById('cve-sort').addEventListener('change', function(e) {
            const sortBy = e.target.value;
            const container = document.querySelector('.cve-container');
            const cards = Array.from(container.querySelectorAll('.cve-card'));
            
            cards.sort((a, b) => {
                if (sortBy === 'score') {
                    const scoreA = parseFloat(a.querySelector('.cve-score').textContent);
                    const scoreB = parseFloat(b.querySelector('.cve-score').textContent);
                    return scoreB - scoreA; // Descending order
                } else if (sortBy === 'id') {
                    const idA = a.querySelector('.cve-id').textContent;
                    const idB = b.querySelector('.cve-id').textContent;
                    return idA.localeCompare(idB);
                }
                return 0;
            });
            
            // Clear container and re-add sorted cards
            container.innerHTML = '';
            cards.forEach(card => container.appendChild(card));
        });
    </script>
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