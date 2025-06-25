# CNA ScoreCard

A static website that provides comprehensive scorecards for CVE Numbering Authorities (CNAs) based on their CVE reporting quality.

## What is a CNA?
A **CVE Numbering Authority (CNA)** is an organization authorized to assign CVE IDs and publish CVE records for vulnerabilities affecting products within their scope. Throughout this documentation, "CNA" refers to a CVE Numbering Authority.

## Overview

CNA ScoreCard is a static website hosted on GitHub Pages that automatically updates every 6 hours with the latest CVE data. The site evaluates CNAs using the Enhanced Aggregate Scoring (EAS) methodology, which measures CVE record quality across five key dimensions: foundational completeness, root cause analysis, severity context, actionable intelligence, and data format precision.

**Note:** This project was inspired by the [CNA Enrichment Recognition program](https://www.cve.org/About/Metrics#CNAEnrichmentRecognition).


## Architecture

### Static Site Generation
- **Data Source**: CVE data is automatically fetched from the official CVEProject/cvelistV5 repository
- **Generation**: A Python script (`generate_static_data.py`) processes the data and creates JSON files
- **Automation**: GitHub Actions workflow runs every 6 hours to update the data and deploy the site
- **Hosting**: The site is served directly from GitHub Pages

### Data Processing
The system generates JSON data files:
- `web/data/cnas.json` - Complete CNA scorecard data with EAS scores
- `web/cna/data/*.json` - Individual CNA data files with their recent CVEs

### Frontend
- Pure HTML, CSS, and JavaScript (no frameworks)
- Responsive design that works on all devices
- Real-time search and sorting functionality
- Color-coded scoring system for easy visualization

## Deployment

The site is automatically deployed to GitHub Pages via GitHub Actions. The workflow:

1. Runs every 6 hours automatically (can also be triggered manually)
2. Fetches the latest CVE data from the official repository
3. Processes the data using the Python analysis engine
4. Generates static JSON files
5. Deploys the updated site to GitHub Pages

## Development

### Prerequisites
- Python 3.11+
- Dependencies listed in `requirements.txt`

### Local Development
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Generate test data: `python cnascorecard/generate_static_data.py`
4. Serve the `web` directory with any static file server

### Manual Data Generation
To generate fresh data locally:
```bash
python cnascorecard/generate_static_data.py
```

This will create the necessary JSON files in the `web/data/` directory.

### Testing Description Quality Algorithm
To test and analyze the description quality scoring algorithm:
```bash
# Install test dependencies
pip install -r tests/test-requirements.txt

# Run the analysis
python tests/run_description_analysis.py
```

This will analyze 10,000 CVE descriptions and provide:
- Statistical analysis of scoring distribution
- Quality category breakdowns
- Component-specific performance metrics
- ML-based clustering analysis (if libraries available)
- Recommendations for algorithm improvements

## Scoring Methodology

The Enhanced Aggregate Scoring (EAS) system evaluates CVE records across six key dimensions:

### 1. Foundational Completeness (30 points)
- Product identification, version details, and clear vulnerability descriptions
- **Enhanced description quality analysis** using multi-dimensional technical content evaluation:
  - **Length & Structure** (3 points): Progressive scoring for descriptions ≥50, ≥100, ≥200 characters
  - **Technical Vulnerability Types** (2 points): Detection of specific vulnerability patterns (buffer overflow, SQL injection, XSS, etc.) - binary scoring
  - **General Technical Terms** (2 points): Progressive scoring for general security terms (vulnerability, exploit, attack, etc.)
  - **Impact/Exploitation Context** (4 points): Progressive scoring for exploitation indicators (allows, enables, execute, etc.)
  - **Technical Specificity** (4 points): Progressive scoring for technical depth indicators (function, parameter, API, module, etc.)
  - **Generic Content Penalty** (-2 points): Penalty for multiple generic phrases in short descriptions
- Checks for vulnerability types, impact context, and technical specificity

### 2. Root Cause Analysis (10 points) 
- CWE classifications and technical depth indicators
- Evaluates presence of proper problem type identification

### 3. Software Identification: (10 points)
- Awarded if a valid CPE identifier is present in the CVE record
- Enables precise product targeting for automation

### 4. Severity & Impact Context (25 points)
- CVSS metrics (v2, v3.0, v3.1, v4.0) with base scores and vector strings
- Impact information and exploitation indicators

### 5. Actionable Intelligence (20% weight)
- Solution information, patch references, and workarounds
- Quality and actionability of reference materials

### 6. Data Format & Precision (5 points)
- Structured data formats and machine-readable content
- Proper formatting of affected products and references
- **All-or-nothing scoring**: Full 5 points only if ALL format requirements are met:
  - Valid CPE identifiers in affected products
  - Complete CVSS format with both baseScore and vectorString
  - Valid CWE identifier format (e.g., CWE-120)
  - Proper language tags in descriptions
  - Well-structured affected products information

CNAs are scored on a 0-100 scale with color coding:
- 🟢 Excellent (80-100)
- 🟡 Good (60-79)
- 🟠 Fair (40-59)
- 🔴 Needs Improvement (0-39)

## Features

- **Main Dashboard**: Overview of CVE statistics and recent vulnerabilities with EAS scores
- **Individual CNA Pages**: Dedicated pages for each CNA showing their last 100 CVEs with detailed EAS breakdowns
- **CVE Cards**: Display CVE ID, EAS score, and detailed score breakdown across all five dimensions
- **Direct CVE Links**: CVE IDs link directly to CVE.org for detailed information
- **Responsive Design**: Works on desktop and mobile devices
- **Real-time Data**: Automatically updated every 6 hours from the official CVE repository

## Project Structure

```
CNAScoreCard/
├── cnascorecard/
│   ├── main.py              # Core analysis engine
│   ├── data_ingestor.py     # CVE data processing
│   ├── eas_scorer.py        # Enhanced Aggregate Scoring implementation
│   └── generate_static_data.py # Static data generation
├── scripts/
│   ├── build.py              # Main build script
│   ├── generate_dashboard.py # Main dashboard generation
│   └── generate_cna_pages.py # Individual CNA page generation
├── web/
│   ├── index.html           # Main dashboard
│   ├── styles.css           # Main styling
│   ├── script.js            # Dashboard functionality
│   ├── scoring.html         # EAS methodology documentation
│   └── cna/                 # Individual CNA pages
│       ├── cna-styles.css   # CNA page styling
│       ├── cna-script.js    # CNA page functionality
│       ├── data/            # Individual CNA data files
│       └── *.html           # Individual CNA pages
├── tests/
│   ├── test_data_structure.py
│   ├── test_integration.py
│   └── test_quick.py
└── README.md
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests to improve the scoring algorithms, add new features, or enhance the user interface.

## License

This project is open source and available under the MIT License.

## Inspiration
This project and its scoring methodology were inspired by the [CNA Enrichment Recognition program](https://www.cve.org/About/Metrics#CNAEnrichmentRecognition).