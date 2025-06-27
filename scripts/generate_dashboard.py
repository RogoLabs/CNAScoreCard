#!/usr/bin/env python3
"""
Generate the main dashboard page
"""

import json
import os
from datetime import datetime
from pathlib import Path

def load_cve_data():
    """Load CVE data from the generated JSON files"""
    try:
        # Try to load the top CVEs data first
        with open('web/data/top100_cves.json', 'r') as f:
            top_cves = json.load(f)
        
        with open('web/data/bottom100_cves.json', 'r') as f:
            bottom_cves = json.load(f)
        
        # Combine for dashboard display - these should have EAS structure
        return top_cves + bottom_cves
    except FileNotFoundError:
        print("CVE data files not found. Please run cnascorecard/generate_static_data.py first.")
        return []

def calculate_statistics(cve_data):
    """Calculate overall statistics"""
    total_cves = len(cve_data)
    
    # Count by severity and collect scores
    severity_counts = {}
    eas_scores = []
    cna_counts = {}
    
    for cve in cve_data:
        # Try to determine severity from CVSS score if available
        cvss_score = None
        if 'scoreBreakdown' in cve and 'severityAndImpactContext' in cve['scoreBreakdown']:
            # This indicates some severity context exists
            pass
        
        # For now, use a simple severity classification
        total_score = cve.get('totalEasScore', 0)
        if total_score >= 80:
            severity = 'Excellent'
        elif total_score >= 60:
            severity = 'Good' 
        elif total_score >= 40:
            severity = 'Fair'
        else:
            severity = 'Poor'
        
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        eas_scores.append(total_score)
        
        cna = cve.get('assigningCna', 'Unknown')
        cna_counts[cna] = cna_counts.get(cna, 0) + 1
    
    avg_score = sum(eas_scores) / len(eas_scores) if eas_scores else 0
    
    return {
        'total_cves': total_cves,
        'severity_counts': severity_counts,
        'average_score': round(avg_score, 2),
        'cna_counts': cna_counts
    }

def generate_dashboard():
    """Generate the main dashboard HTML"""
    print("Generating main dashboard...")
    
    # Load CVE data
    cve_data = load_cve_data()
    if not cve_data:
        return
    
    # Calculate statistics
    stats = calculate_statistics(cve_data)
    
    # Get recent CVEs (last 50)
    recent_cves = sorted(cve_data, key=lambda x: x.get('datePublished', ''), reverse=True)[:50]
    
    # Generate HTML
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CNA Score Card</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="styles.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <h1 class="text-center mb-4">CNA Score Card</h1>
                <p class="text-center lead">Comprehensive CVE Analysis Dashboard</p>
                
                <div class="text-center mb-4">
                    <a href="cna/index.html" class="btn btn-primary">Browse CNAs</a>
                </div>
                
                <!-- Statistics Cards -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card bg-primary text-white">
                            <div class="card-body text-center">
                                <h5 class="card-title">Total CVEs</h5>
                                <h2>{stats['total_cves']:,}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-info text-white">
                            <div class="card-body text-center">
                                <h5 class="card-title">Average Score</h5>
                                <h2>{stats['average_score']}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-warning text-white">
                            <div class="card-body text-center">
                                <h5 class="card-title">Critical CVEs</h5>
                                <h2>{stats['severity_counts'].get('Critical', 0)}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card bg-success text-white">
                            <div class="card-body text-center">
                                <h5 class="card-title">Total CNAs</h5>
                                <h2>{len(stats['cna_counts'])}</h2>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Recent CVEs Section -->
                <h2 class="mb-3">Recent CVEs</h2>
                <div class="row">
"""

    # Add recent CVE cards
    for cve in recent_cves:
        cve_id = cve.get('cveId', 'N/A')
        total_score = cve.get('totalEasScore', 0)
        
        # Determine card color based on score
        card_class = "border-secondary"
        if total_score >= 80:
            card_class = "border-success"
        elif total_score >= 60:
            card_class = "border-info"
        elif total_score >= 40:
            card_class = "border-warning"
        else:
            card_class = "border-danger"
        
        html_content += f"""
                    <div class="col-md-6 col-lg-4 mb-3">
                        <div class="card {card_class}">
                            <div class="card-body">
                                <h6 class="card-title">
                                    <a href="https://www.cve.org/CVERecord?id={cve_id}" 
                                       target="_blank" class="text-decoration-none">
                                        {cve_id}
                                    </a>
                                </h6>
                                <div class="row">
                                    <div class="col-6">
                                        <small class="text-muted">EAS Score</small>
                                        <div class="fw-bold">{total_score:.1f}/100</div>
                                    </div>
                                    <div class="col-6">
                                        <small class="text-muted">CNA</small>
                                        <div class="fw-bold">{cve.get('assigningCna', 'Unknown')}</div>
                                    </div>
                                </div>
                                <div class="row mt-2">
                                    <div class="col-6">
                                        <small class="text-muted">Foundational</small>
                                        <div class="fw-bold">{cve.get('scoreBreakdown', {}).get('foundationalCompleteness', 0):.1f}/30</div>
                                    </div>
                                    <div class="col-6">
                                        <small class="text-muted">Root Cause</small>
                                        <div class="fw-bold">{cve.get('scoreBreakdown', {}).get('rootCauseAnalysis', 0):.1f}/10</div>
                                    </div>
                                </div>
                                <div class="mt-2">
                                    <small class="text-muted">Published</small>
                                    <div class="small">{cve.get('datePublished', 'N/A')}</div>
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

    # Ensure web directory exists
    web_dir = Path('web')
    web_dir.mkdir(exist_ok=True)
    
    # Write the HTML file
    with open(web_dir / 'index.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"Dashboard generated with {len(recent_cves)} recent CVEs")

def main():
    generate_dashboard()

if __name__ == "__main__":
    main()