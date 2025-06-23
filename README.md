# CNA ScoreCard

A static website that provides comprehensive scorecards for Certificate Numbering Authorities (CNAs) based on their CVE reporting quality.

## Overview

CNA ScoreCard is now a static website hosted on GitHub Pages that automatically updates every 6 hours with the latest CVE data. The site evaluates CNAs based on various metrics including response time, data quality, and reporting consistency.

## Architecture

### Static Site Generation
- **Data Source**: CVE data is automatically fetched from the official CVEProject/cvelistV5 repository
- **Generation**: A Python script (`generate_static_data.py`) processes the data and creates JSON files
- **Automation**: GitHub Actions workflow runs every 6 hours to update the data and deploy the site
- **Hosting**: The site is served directly from GitHub Pages

### Data Processing
The system generates three main data files:
- `web/data/cnas.json` - Complete CNA scorecard data
- `web/data/top100_cves.json` - Top 100 CVEs by score
- `web/data/bottom100_cves.json` - Bottom 100 CVEs by score

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
3. Generate test data: `python generate_static_data.py`
4. Serve the `web` directory with any static file server

### Manual Data Generation
To generate fresh data locally:
```bash
python generate_static_data.py
```

This will create the necessary JSON files in the `web/data/` directory.

## Scoring Methodology

CNAs are evaluated based on multiple factors:
- **Data Quality**: Completeness and accuracy of CVE information
- **References Quality**: Presence and quality of reference materials
- **Description Readability**: Clarity and completeness of vulnerability descriptions
- **Consistency**: Regular and reliable reporting patterns

Scores range from 0-10, with color coding:
- 🟢 Excellent (8.0+)
- 🟡 Good (6.0-7.9)
- 🟠 Fair (4.0-5.9)
- 🔴 Needs Improvement (<4.0)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests to improve the scoring algorithms, add new features, or enhance the user interface.

## License

This project is open source and available under the MIT License.