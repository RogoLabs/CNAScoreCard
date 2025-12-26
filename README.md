<p align="center">
  <img src="web/assets/logo.svg" alt="CNA Scorecard Logo" width="120" height="120">
</p>

<h1 align="center">CNA Scorecard</h1>

<p align="center">
  <strong>Measuring CVE Data Quality Across the Vulnerability Ecosystem</strong>
</p>

<p align="center">
  <a href="https://cnascorecard.org">🌐 Live Site</a> •
  <a href="https://cnascorecard.org/cna/">🏆 Leaderboard</a> •
  <a href="https://cnascorecard.org/scoring.html">📖 Methodology</a> •
  <a href="https://cnascorecard.org/badges.html">🏅 Get Your Badge</a>
</p>

<p align="center">
  <a href="https://github.com/RogoLabs/CNAScoreCard/actions/workflows/run-pipeline.yml">
    <img src="https://github.com/RogoLabs/CNAScoreCard/workflows/Scheduled%20Data%20Pipeline/badge.svg" alt="Pipeline Status">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
  </a>
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/data-updated%20every%206h-green.svg" alt="Data Freshness">
</p>

---

## 🎯 What is CNA Scorecard?

**CNA Scorecard** is an automated system that measures how completely CVE Numbering Authorities (CNAs) populate vulnerability records. By analyzing the **most recent 6 months** of CVE data, we provide transparent, data-driven insights that help:

- **Security Teams** → Understand which CNAs provide the most actionable vulnerability data
- **CNAs** → Identify areas for improvement in their disclosure practices  
- **Researchers** → Track ecosystem-wide trends in vulnerability data quality
- **Organizations** → Make informed decisions about vulnerability prioritization

> 💡 **Why 6 months?** We focus on recent data to reflect current CNA practices, not historical baggage. This gives CNAs credit for improvements and provides users with relevant, actionable insights.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| 🏆 **CNA Rankings** | Live leaderboard of 300+ CNAs ranked by data completeness |
| 📊 **5-Category Scoring** | Comprehensive scoring across foundational, root cause, severity, software ID, and patch info |
| 📈 **Trend Analysis** | Track how CNA performance evolves over time with rolling 7-day charts |
| 🔍 **Individual Profiles** | Deep-dive into any CNA's recent CVEs with per-record scoring |
| 📱 **Mobile-First Design** | Fully responsive interface optimized for all devices |
| 🏅 **Embeddable Badges** | SVG badges CNAs can display on their sites (auto-updated every 6h) |
| 📤 **Data Export** | Download rankings and CVE data in CSV or JSON format |
| ♿ **Accessible** | WCAG-compliant with skip links, ARIA labels, and keyboard navigation |
| ⚡ **Always Fresh** | Automated pipeline updates data every 6 hours via GitHub Actions |

---

## 📊 Scoring Methodology

Each CVE record is scored on a **100-point scale** across five categories:

```
┌─────────────────────────────────────────────────────────────────┐
│  FOUNDATIONAL COMPLETENESS (50 pts)                             │
│  ├── Description quality and detail                             │
│  ├── Affected products clearly identified                       │
│  └── Reference URLs provided                                    │
├─────────────────────────────────────────────────────────────────┤
│  ROOT CAUSE ANALYSIS (15 pts)                                   │
│  └── CWE (Common Weakness Enumeration) identifier               │
├─────────────────────────────────────────────────────────────────┤
│  SEVERITY & IMPACT (15 pts)                                     │
│  └── CVSS score with vector string                              │
├─────────────────────────────────────────────────────────────────┤
│  SOFTWARE IDENTIFICATION (10 pts)                               │
│  └── CPE identifiers (supports CVE 5.1 cpeApplicability)        │
├─────────────────────────────────────────────────────────────────┤
│  PATCH INFORMATION (10 pts)                                     │
│  └── References tagged as patches/fixes                         │
└─────────────────────────────────────────────────────────────────┘
```

**Grade Thresholds:**
- 🥇 **A+ (97-100%)** - Exceptional data quality
- 🥈 **A (90-96%)** - Excellent completeness
- 🥉 **B (80-89%)** - Good, room for improvement
- **C (70-79%)** - Adequate but missing key fields
- **D (60-69%)** - Below expectations
- **F (<60%)** - Significant data gaps

> 📖 Full methodology details: [cnascorecard.org/scoring.html](https://cnascorecard.org/scoring.html)

---

## 🚀 Quick Start

### View the Live Scorecard

Visit **[cnascorecard.org](https://cnascorecard.org)** to explore CNA rankings, trends, and individual profiles.

### Run Locally

```bash
# Clone the repository
git clone https://github.com/RogoLabs/CNAScoreCard.git
cd CNAScoreCard

# Install Python dependencies
pip install -r requirements.txt

# Run the data pipeline (analyzes last 6 months of CVE data)
python cnascorecard_pipeline/pipeline.py

# Serve the web interface
cd web && python -m http.server 8000
# Open http://localhost:8000 in your browser
```

### Run with Custom Date Range

```bash
python cnascorecard_pipeline/pipeline.py \
  --start-date 2024-01-01 \
  --end-date 2024-06-30 \
  --output-dir ./custom-output
```

---

## 🏅 CNA Badges

Display your CNA Scorecard rating on your website, README, or security advisories:

<p align="center">
  <img src="https://img.shields.io/badge/CNA%20Rank-%231-gold" alt="Example Rank Badge">
  <img src="https://img.shields.io/badge/CNA%20Score-95.0%25-brightgreen" alt="Example Score Badge">
</p>

### Get Your Badge

1. Visit the [Badge Generator](https://cnascorecard.org/badges.html)
2. Search for your CNA
3. Copy the Markdown or HTML code

**Markdown Example:**
```markdown
[![CNA Scorecard](https://cnascorecard.org/badges/YourCNA-rank.svg)](https://cnascorecard.org/cna/cna-detail.html?shortName=YourCNA)
```

**HTML Example:**
```html
<a href="https://cnascorecard.org/cna/cna-detail.html?shortName=YourCNA">
  <img src="https://cnascorecard.org/badges/YourCNA-combined.svg" alt="CNA Scorecard">
</a>
```

Badges are **color-coded** by score and **auto-update** every 6 hours.

---

## 🏗️ Architecture

```
CNAScoreCard/
├── cnascorecard_pipeline/     # Python data pipeline
│   ├── pipeline.py            # Main orchestrator
│   ├── ingest.py              # CVE data loading & filtering
│   ├── scoring.py             # 5-category scoring engine
│   ├── aggregation.py         # CNA statistics & rankings
│   ├── completeness.py        # Field utilization analysis
│   ├── trends.py              # Historical trend calculations
│   └── config.py              # Configuration & rules
│
├── web/                       # Static web frontend
│   ├── index.html             # Homepage dashboard
│   ├── cna/                   # CNA leaderboard & profiles
│   ├── completeness/          # Field completeness analysis
│   ├── trends.html            # Performance trend charts
│   ├── scoring.html           # Methodology documentation
│   ├── badges.html            # Badge generator
│   └── data/                  # JSON data files (auto-generated)
│
├── cve_data/                  # CVE source data (gitignored)
└── .github/workflows/         # GitHub Actions automation
```

### Data Flow

```
CVEProject/cvelistV5 → Ingest → Score → Aggregate → JSON → Web Frontend
        ↑                                              ↓
        └──────── GitHub Actions (every 6 hours) ──────┘
```

---

## 📁 Data Files

The pipeline generates structured JSON files in `web/data/`:

| File | Description |
|------|-------------|
| `cna_combined.json` | Complete CNA data with scores and metadata |
| `cna_summary.json` | Lightweight rankings for the leaderboard |
| `cna_list.json` | Official CNA registry information |
| `field_utilization.json` | CVE field usage statistics |
| `performance_trends.json` | Daily scoring trends |
| `top_improvers.json` | CNAs with biggest improvements |
| `completeness_summary.json` | Analysis period metadata |
| `cna/{shortName}.json` | Individual CNA detailed profiles |

> 📖 Full schema documentation: [web/data/README.md](web/data/README.md)

---

## 🤝 Contributing

We welcome contributions from the cybersecurity community!

### Ways to Contribute

- 🐛 **Report bugs** via [GitHub Issues](https://github.com/RogoLabs/CNAScoreCard/issues)
- 💡 **Suggest features** or improvements
- 📝 **Improve documentation**
- 🔧 **Submit pull requests**

### Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR-USERNAME/CNAScoreCard.git
cd CNAScoreCard

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt

# Run tests
cd cnascorecard_pipeline
pytest

# Run the pipeline
python pipeline.py
```

### Code Style

- Python: Follow PEP 8, use type hints
- JavaScript: ES6+, no external frameworks
- CSS: Use CSS custom properties from `theme.css`

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by the [CVE CNA Enrichment Recognition Program](https://www.cve.org/About/Metrics#CNAEnrichmentRecognition)
- Built on data from the [CVE Program](https://www.cve.org/) and [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)
- Thanks to the global cybersecurity community for their commitment to better vulnerability disclosure

---

<p align="center">
  <strong>Made with ❤️ for the cybersecurity community</strong>
</p>

<p align="center">
  <a href="https://cnascorecard.org">Visit CNA Scorecard</a> •
  <a href="https://github.com/RogoLabs/CNAScoreCard/issues">Report an Issue</a> •
  <a href="https://github.com/RogoLabs/CNAScoreCard/discussions">Discussions</a>
</p>
