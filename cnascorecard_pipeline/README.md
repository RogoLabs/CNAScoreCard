# CNA Scorecard Pipeline

A modern, production-ready Python pipeline for analyzing CVE data quality and generating CNA (CVE Numbering Authority) performance scorecards.

## Overview

The CNA Scorecard Pipeline processes CVE (Common Vulnerabilities and Exposures) data to evaluate how well CNAs provide complete and useful vulnerability information. It generates comprehensive reports, rankings, and visualizations to help improve CVE data quality across the ecosystem.

### Key Features

- **Modular Architecture**: Clean separation of concerns with dedicated modules for ingestion, scoring, aggregation, and output
- **Comprehensive Scoring**: Multi-category scoring system evaluating foundational completeness, root cause analysis, software identification, severity context, and patch information
- **Flexible Configuration**: Centralized configuration management with customizable scoring rules and field mappings
- **Robust Error Handling**: Graceful error handling with detailed logging and recovery mechanisms
- **CI/CD Ready**: Single-command execution with comprehensive testing and validation
- **Production Quality**: Type hints, comprehensive documentation, and modern Python best practices

## Quick Start

### Prerequisites

- Python 3.8 or higher
- CVE data files in JSON format (typically from the CVE Project repository)

### Installation

1. Clone the repository and navigate to the pipeline directory:
```bash
cd cnascorecard_pipeline
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Verify installation by running tests:
```bash
pytest
```

### Basic Usage

Run the pipeline with default settings (analyzes last 6 months):
```bash
python pipeline.py
```

Run with custom date range:
```bash
python pipeline.py --start-date 2024-01-01 --end-date 2024-06-30
```

Run with custom output directory:
```bash
python pipeline.py --output-dir /path/to/output
```

## Architecture

### Core Modules

#### `pipeline.py` - Main Orchestration
The primary entry point that coordinates all pipeline stages:
- **CNAScoreCardPipeline**: Main pipeline class with modular execution stages
- **Command-line interface**: Supports date ranges, output directories, and logging levels
- **Error handling**: Comprehensive error handling with custom `PipelineError` exception
- **Progress tracking**: Detailed logging and execution summaries

#### `config.py` - Configuration Management
Centralized configuration for all pipeline components:
- **File paths**: Configurable input/output directories
- **Scoring rules**: Loaded from `rules.json` with validation
- **Field mappings**: CVE schema field definitions and importance levels
- **Logging configuration**: Structured logging setup

#### `ingest.py` - Data Loading
CVE data ingestion and preprocessing:
- **`load_cve_records()`**: Loads CVE JSON files with optional date filtering
- **`extract_cna_short_names()`**: Extracts unique CNA identifiers from CVE data
- **Date filtering**: Efficient filtering by publication date ranges
- **Validation**: CVE record structure validation and error handling

#### `scoring.py` - CVE Scoring
Multi-category scoring system for CVE records:
- **`score_cve_record()`**: Scores individual CVE records across all categories
- **`score_multiple_cves()`**: Batch scoring with progress tracking
- **Category functions**: Dedicated scoring functions for each category
- **Configurable rules**: Uses scoring rules from configuration

#### `aggregation.py` - CNA Analysis
Aggregates scored CVEs by CNA and generates summaries:
- **`aggregate_cna_scores()`**: Groups CVEs by CNA and calculates statistics
- **Trend analysis**: Compares current performance with historical data
- **Ranking system**: Generates CNA rankings with percentiles
- **Metadata integration**: Enriches CNA data with official metadata

#### `completeness.py` - Field Analysis
Analyzes CVE field utilization and completeness:
- **`compute_field_utilization()`**: Calculates field usage statistics across all CVEs
- **`compute_individual_cna_field_utilization()`**: Per-CNA field utilization analysis
- **Schema mapping**: Maps CVE fields to importance categories
- **Nested field support**: Handles complex nested JSON structures

#### `utils.py` - Utilities
Common utilities and helper functions:
- **Logging setup**: Configures structured logging with timestamps
- **File operations**: JSON file reading/writing with error handling
- **Data validation**: CVE record validation and sanitization
- **Progress tracking**: Progress bar utilities for long-running operations

### Data Flow

```
CVE JSON Files → Ingest → Filter by Date → Score Records → Aggregate by CNA → Generate Outputs
                    ↓
                Configuration ← Rules & Field Mappings
                    ↓
                Completeness Analysis → Field Utilization Reports
```

## Configuration

### Main Configuration (`config.py`)

The pipeline uses centralized configuration loaded from `config.py`:

```python
# Example configuration structure
CONFIG = {
    'directories': {
        'cve_data': '../cve_data',
        'web_data': '../web/data',
        'completeness': '../web/data/completeness',
        'cna_data': '../web/data/cna'
    },
    'scoring': {
        'rules_file': 'rules.json',
        'cwe_ids_file': 'cwe_ids.json'
    },
    'analysis': {
        'default_period_months': 6,
        'trend_periods': 3
    }
}
```

### Scoring Rules (`rules.json`)

Defines scoring weights and criteria for each category:

```json
{
  "foundationalCompleteness": {
    "weight": 50,
    "fields": ["descriptions", "affected", "references"],
    "requirements": {
      "descriptions": {"min_length": 50},
      "affected": {"required": true},
      "references": {"min_count": 1}
    }
  }
}
```

### Field Mappings

CVE schema fields are mapped to scoring categories and importance levels:

```python
CANONICAL_FIELDS = [
    {
        'field': 'containers.cna.descriptions',
        'importance': 'High',
        'description': 'Vulnerability descriptions',
        'cna_scorecard_category': 'foundationalCompleteness'
    }
]
```

## Output Files

The pipeline generates several output files for web interface consumption:

### Individual CNA Files (`/web/data/cna/{cna_name}.json`)
Detailed information for each CNA:
```json
{
  "cna_info": [{
    "shortName": "example-cna",
    "organizationName": "Example Organization",
    "total_cves": 150,
    "rank": 5,
    "percentile": 85.2
  }],
  "cna_scoring": [{
    "overall_average_score": 78.5,
    "average_foundational_completeness": 45.2,
    "trend_direction": "improving"
  }],
  "cve_scoring": [
    {
      "cveId": "CVE-2024-0001",
      "totalCveScore": 85,
      "scoreBreakdown": {...}
    }
  ]
}
```

### Summary Files
- **`cna_combined.json`**: Combined CNA rankings and metadata
- **`completeness_summary.json`**: Overall field utilization statistics

### Completeness Files (`/web/data/completeness/`)
- **`field_utilization.json`**: Field usage statistics across all CNAs
- **`{cna_name}.json`**: Per-CNA field utilization details

## Testing

### Test Structure

The pipeline includes comprehensive unit tests:

```
tests/
├── __init__.py
├── test_scoring.py      # Scoring logic tests
├── test_aggregation.py  # CNA aggregation tests  
├── test_ingest.py       # Data loading tests
└── test_pipeline.py     # Integration tests
```

### Running Tests

Run all tests:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=. --cov-report=html
```

Run specific test file:
```bash
pytest tests/test_scoring.py -v
```

### Test Features

- **Mock data fixtures**: Tests use synthetic data, not production files
- **Comprehensive coverage**: Tests cover normal operations, edge cases, and error conditions
- **Integration tests**: Full pipeline execution testing
- **Performance tests**: Validates pipeline performance with large datasets

## Development

### Code Quality

The pipeline follows modern Python development practices:

- **Type hints**: All functions include comprehensive type annotations
- **Documentation**: Google-style docstrings for all public functions
- **Code formatting**: Black code formatter with 88-character line length
- **Linting**: Flake8 for code quality checks
- **Import sorting**: isort for consistent import organization

### Development Tools

Install development dependencies:
```bash
pip install -r requirements.txt  # Includes dev tools
```

Format code:
```bash
black .
isort .
```

Run linting:
```bash
flake8 .
mypy .
```

### Adding New Features

1. **Scoring Categories**: Add new scoring functions to `scoring.py` and update `rules.json`
2. **Output Formats**: Extend output generation in `pipeline.py`
3. **Data Sources**: Modify ingestion logic in `ingest.py`
4. **Analysis Types**: Add new analysis functions to `completeness.py` or `aggregation.py`

## Deployment

### CI/CD Integration

The pipeline is designed for automated execution:

```yaml
# Example GitHub Actions workflow
- name: Run CNA Scorecard Pipeline
  run: |
    cd cnascorecard_pipeline
    python pipeline.py --log-level INFO
    
- name: Validate Output
  run: |
    cd cnascorecard_pipeline
    pytest tests/test_pipeline.py::TestPipelineOutputs
```

### Production Considerations

- **Resource Requirements**: Pipeline processes ~300K CVE records, requires ~2GB RAM
- **Execution Time**: Full pipeline run takes 5-15 minutes depending on data size
- **Storage**: Output files require ~50MB for typical 6-month analysis
- **Monitoring**: Comprehensive logging enables production monitoring

### Environment Variables

Optional environment variables for production deployment:

```bash
export CVE_DATA_DIR="/path/to/cve/data"
export WEB_OUTPUT_DIR="/path/to/web/data"
export LOG_LEVEL="INFO"
export CONFIG_FILE="/path/to/custom/config.py"
```

## Troubleshooting

### Common Issues

**No CVE records found**
- Verify CVE data directory exists and contains JSON files
- Check date range parameters
- Ensure CVE files follow expected naming convention

**Scoring errors**
- Validate `rules.json` format
- Check `cwe_ids.json` for required CWE identifiers
- Review CVE record structure for required fields

**Memory issues**
- Reduce date range for analysis
- Increase system memory allocation
- Consider processing in smaller batches

### Debug Mode

Enable detailed debugging:
```bash
python pipeline.py --log-level DEBUG
```

This provides extensive logging including:
- CVE record processing details
- Scoring calculations for each category
- CNA aggregation statistics
- File I/O operations

### Performance Optimization

For large datasets:
- Use date filtering to reduce CVE record count
- Enable progress tracking for long operations
- Consider parallel processing for scoring (future enhancement)

## Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Install development dependencies
4. Make changes with tests
5. Run quality checks
6. Submit pull request

### Code Standards

- Follow PEP 8 style guidelines
- Add type hints to all functions
- Include comprehensive docstrings
- Write tests for new functionality
- Update documentation as needed

## License

This project is part of the CNA Scorecard initiative to improve CVE data quality across the cybersecurity ecosystem.

## Support

For questions or issues:
- Review this documentation
- Check existing GitHub issues
- Run tests to validate setup
- Enable debug logging for troubleshooting
