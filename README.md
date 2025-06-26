# CNA ScoreCard

**Comprehensive, data-driven scorecards for CVE Numbering Authorities (CNAs) — empowering transparency and quality in vulnerability reporting.**

**🌐 Live Site:** [cnascorecard.org](https://cnascorecard.org)

---

## Table of Contents
- [What is a CNA?](#what-is-a-cna)
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Deployment](#deployment)
- [Development](#development)
- [Scoring Methodology](#scoring-methodology)
- [Features](#features)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)
- [Related Resources](#related-resources)
- [Inspiration](#inspiration)

## What is a CNA?
A **CVE Numbering Authority (CNA)** is an organization authorized to assign CVE IDs and publish CVE records for vulnerabilities affecting products within their scope. Throughout this documentation, "CNA" refers to a CVE Numbering Authority.

## Overview

CNA ScoreCard is an open-source, fully automated static website that evaluates and visualizes the quality of CVE reporting by CNAs worldwide. Updated every 6 hours, it leverages the Enhanced Aggregate Scoring (EAS) methodology to provide transparent, actionable insights into CVE record quality across six key dimensions.

**Why CNA ScoreCard?**
- **Transparency:** Shine a light on the quality of vulnerability reporting across the ecosystem.
- **Accountability:** Help CNAs identify strengths and areas for improvement.
- **Automation:** No manual intervention required—always up to date.

**Note:** Inspired by the [CNA Enrichment Recognition program](https://www.cve.org/About/Metrics#CNAEnrichmentRecognition).

## Quick Start

Get up and running locally in minutes:

```bash
# Clone the repository
 git clone https://github.com/gamblin/CNAScoreCard.git
 cd CNAScoreCard

# Install dependencies
 pip install -r requirements.txt

# Generate static data
 python cnascorecard/generate_static_data.py

# Serve the web directory (example using Python)
 cd web
 python -m http.server 8000
```

Visit [http://localhost:8000](http://localhost:8000) to view the dashboard.

## Architecture

### Static Site Generation
- **Data Source:** CVE data is fetched from the official CVEProject/cvelistV5 repository
- **Processing:** Python scripts analyze and score the data, generating JSON files
- **Automation:** GitHub Actions workflow updates and deploys the site every 6 hours
- **Hosting:** Served via GitHub Pages for maximum reliability and reach

### Data Processing
- `web/data/cnas.json` — Complete CNA scorecard data with EAS scores
- `web/cna/data/*.json` — Individual CNA data files with their recent CVEs

### Frontend
- Pure HTML, CSS, and JavaScript (no frameworks)
- Responsive, mobile-friendly design
- Real-time search, sorting, and color-coded scoring

## Deployment

The site is automatically deployed to GitHub Pages via GitHub Actions:
1. Runs every 6 hours (or manually)
2. Fetches the latest CVE data
3. Processes and scores the data
4. Generates static JSON files
5. Deploys the updated site

## Development

### Prerequisites
- Python 3.11+
- Dependencies in `requirements.txt`

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

This creates the necessary JSON files in `web/data/`.

### Testing Description Quality Algorithm
To test and analyze the description quality scoring algorithm:
```bash
# Install test dependencies
pip install -r tests/test-requirements.txt

# Run the analysis
python tests/run_description_analysis.py
```

This analyzes 10,000 CVE descriptions and provides:
- Statistical scoring distribution
- Quality category breakdowns
- Component-specific metrics
- ML-based clustering (if available)
- Recommendations for improvements

## Scoring Methodology

The Enhanced Aggregate Scoring (EAS) system evaluates CVE records across six key dimensions:

### 1. Foundational Completeness (30 points)
- Product identification, version details, and clear vulnerability descriptions
- **Enhanced description quality analysis** using multi-dimensional technical content evaluation based on analysis of 9,435 CVE descriptions:
  - **Length & Structure** (3 points): Progressive scoring for descriptions ≥50, ≥100, ≥200 characters
  - **Technical Vulnerability Types** (4 points): Detection of 47 specific vulnerability patterns (e.g., file inclusion, SQL injection, XSS, buffer overflow, privilege escalation, cryptographic issues)
  - **Impact/Exploitation Context** (4 points): Progressive scoring for 36 exploitation indicators (e.g., "leads to", "execute arbitrary", "allows", "bypass", "unauthorized access")
  - **Technical Specificity** (4 points): Progressive scoring for 52 technical depth indicators (e.g., "function", "parameter", "API", "when processing", "authentication mechanism")
  - **Generic Content Penalty** (-2 points): Penalty for 12 generic phrases in short descriptions (e.g., "vulnerability exists", "security issue")
- Data-driven term selection based on high vs. low quality CVE descriptions

### 2. Root Cause Analysis (10 points)
- CWE classifications and technical depth indicators
- Evaluates presence of proper problem type identification

### 3. Software Identification (10 points)
- Awarded if a valid CPE identifier is present in the CVE record
- Enables precise product targeting for automation

### 4. Severity & Impact Context (25 points)
- CVSS metrics (v2, v3.0, v3.1, v4.0) with base scores and vector strings
- Impact information and exploitation indicators

### 5. Actionable Intelligence (20% weight)
- Solution information, patch references, and workarounds
- Quality and actionability of reference materials

### 6. Data Format & Precision (5 points)
- Structured, machine-readable content
- Proper formatting of affected products and references
- **All-or-nothing scoring:** Full 5 points only if ALL format requirements are met:
  - Valid CPE identifiers in affected products
  - Complete CVSS format with both baseScore and vectorString
  - Valid CWE identifier format (e.g., CWE-120)
  - Proper language tags in descriptions
  - Well-structured affected products information

**Scoring Scale:**
- 🟢 Excellent (80-100)
- 🟡 Good (60-79)
- 🟠 Fair (40-59)
- 🔴 Needs Improvement (0-39)

## Features

- **Main Dashboard:** Overview of CVE statistics and recent vulnerabilities with EAS scores
- **Individual CNA Pages:** Dedicated pages for each CNA showing their last 100 CVEs with detailed EAS breakdowns
- **CVE Cards:** Display CVE ID, EAS score, and detailed score breakdown
- **Direct CVE Links:** CVE IDs link directly to CVE.org
- **Responsive Design:** Works on desktop and mobile
- **Real-time Data:** Updated every 6 hours from the official CVE repository

## Project Structure

```text
CNAScoreCard/
├── cnascorecard/
│   ├── main.py              # Core analysis engine
│   ├── data_ingestor.py     # CVE data processing
│   ├── eas_scorer.py        # Enhanced Aggregate Scoring implementation
│   └── generate_static_data.py # Static data generation
├── scripts/
│   ├── build.py              # Main build script
│   └── generate_dashboard.py # Main dashboard generation
├── web/
│   ├── index.html           # Main dashboard
│   ├── styles.css           # Main styling
│   ├── script.js            # Dashboard functionality
│   ├── scoring.html         # EAS methodology documentation
│   └── cna/                 # CNA pages
│       ├── cna-detail.html  # Unified CNA detail page
│       ├── cna-styles.css   # CNA page styling
│       ├── cna-script.js    # CNA page functionality
│       ├── index.html       # CNA directory page
│       └── data/            # Individual CNA data files
├── tests/
│   ├── test_data_structure.py
│   ├── test_integration.py
│   └── test_quick.py
└── README.md
```

## Contributing

Contributions are welcome! Please open issues or pull requests to improve scoring, add features, or enhance the UI. See [CONTRIBUTING.md](CONTRIBUTING.md) if available.

## Security Best Practices
- All user input and dynamic content is escaped to prevent XSS.
- Dependencies are kept up to date to avoid known vulnerabilities.
- File and network resources are managed with context managers.
- No sensitive data is stored or processed.

## License

This project is open source under the MIT License.

## Related Resources

- [Measuring CVE Performance](https://bjedwards.observablehq.cloud/measuring-cna-performance/) by [Ben Edwards](https://www.bitsight.com/trace/team/ben-edwards) — Analysis of CNA performance metrics

## Inspiration
This project and its scoring methodology were inspired by the [CNA Enrichment Recognition program](https://www.cve.org/About/Metrics#CNAEnrichmentRecognition).

---

## Contact & Support

For questions, feedback, or support, please open an [issue](https://github.com/gamblin/CNAScoreCard/issues) or contact the maintainer via GitHub.

[![Build Status](https://github.com/gamblin/CNAScoreCard/actions/workflows/main.yml/badge.svg)](https://github.com/gamblin/CNAScoreCard/actions)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
