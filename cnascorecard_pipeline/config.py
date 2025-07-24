"""
Configuration management for CNA Scorecard Pipeline.

This module centralizes all configuration values, file paths, and scoring rules
to improve maintainability and make the pipeline more configurable.
"""
import os
import json
from typing import Dict, Any, List
from pathlib import Path

# Base directories
PIPELINE_DIR = Path(__file__).parent
PROJECT_ROOT = PIPELINE_DIR.parent
CVE_DATA_DIR = PROJECT_ROOT / "cve_data"
WEB_DATA_DIR = PROJECT_ROOT / "web" / "data"

# Configuration file paths
RULES_FILE = PIPELINE_DIR / "rules.json"
CWE_IDS_FILE = PIPELINE_DIR / "cwe_ids.json"
CNA_LIST_FILE = WEB_DATA_DIR / "cna_list.json"

# Output directories
COMPLETENESS_DIR = WEB_DATA_DIR / "completeness"
CNA_DATA_DIR = WEB_DATA_DIR / "cna"

# Date configuration
DATE_FORMAT = "%Y-%m-%d"
ANALYSIS_PERIOD_MONTHS = 6

# Scoring configuration
class ScoringConfig:
    """Configuration for CVE scoring logic."""
    
    def __init__(self):
        self._rules = self._load_scoring_rules()
        self._valid_cwe_ids = self._load_valid_cwe_ids()
    
    def _load_scoring_rules(self) -> Dict[str, Any]:
        """Load scoring rules from rules.json."""
        try:
            with open(RULES_FILE, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Scoring rules file not found: {RULES_FILE}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in scoring rules file: {e}")
    
    def _load_valid_cwe_ids(self) -> set:
        """Load valid CWE IDs from cwe_ids.json."""
        try:
            with open(CWE_IDS_FILE, 'r') as f:
                return set(json.load(f))
        except FileNotFoundError:
            raise FileNotFoundError(f"CWE IDs file not found: {CWE_IDS_FILE}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in CWE IDs file: {e}")
    
    @property
    def rules(self) -> Dict[str, Any]:
        """Get scoring rules."""
        return self._rules
    
    @property
    def valid_cwe_ids(self) -> set:
        """Get valid CWE IDs."""
        return self._valid_cwe_ids
    
    def get_category_weight(self, category: str) -> int:
        """Get weight for a scoring category."""
        return self._rules.get(category, {}).get('weight', 0)
    
    def get_category_criteria(self, category: str) -> List[str]:
        """Get criteria for a scoring category."""
        return self._rules.get(category, {}).get('criteria', [])

# Field mapping for CNA Scorecard categories
CNA_SCORECARD_FIELDS = {
    # Foundational Completeness (50% weight)
    'containers.cna.descriptions': 'foundationalCompleteness',
    'containers.cna.affected': 'foundationalCompleteness',
    'containers.cna.references': 'foundationalCompleteness',
    
    # Root Cause Analysis (15% weight)
    'problemTypes.cwe': 'rootCauseAnalysis',
    
    # Severity and Impact Context (15% weight)
    'metrics.cvssV3_0': 'severityAndImpactContext',
    'metrics.cvssV3_1': 'severityAndImpactContext',
    'metrics.cvssV4_0': 'severityAndImpactContext',
    
    # Software Identification (10% weight)
    'affected.cpes': 'softwareIdentification',
    
    # Patch Information (10% weight)
    'references.patch': 'patchinfo',
}

# Canonical fields for completeness analysis
CANONICAL_FIELDS = [
    # CNA ScoreCard Measured Fields (High-Level Criteria Only)
    {"field": "containers.cna.descriptions", "importance": "High", "description": "Vulnerability descriptions", "cna_scorecard_category": "foundationalCompleteness"},
    {"field": "containers.cna.affected", "importance": "High", "description": "Affected products and versions", "cna_scorecard_category": "foundationalCompleteness"},
    {"field": "containers.cna.references", "importance": "High", "description": "Patch Info URLs and documentation", "cna_scorecard_category": "foundationalCompleteness"},
    {"field": "problemTypes.cwe", "importance": "High", "description": "Common Weakness Enumeration identifiers", "cna_scorecard_category": "rootCauseAnalysis"},
    {"field": "metrics.cvssV3_1", "importance": "High", "description": "CVSS v3.1 metrics", "cna_scorecard_category": "severityAndImpactContext"},
    {"field": "metrics.cvssV3_0", "importance": "High", "description": "CVSS v3.0 metrics", "cna_scorecard_category": "severityAndImpactContext"},
    {"field": "metrics.cvssV4_0", "importance": "High", "description": "CVSS v4.0 metrics", "cna_scorecard_category": "severityAndImpactContext"},
    {"field": "affected.cpes", "importance": "High", "description": "Common Platform Enumeration identifiers", "cna_scorecard_category": "softwareIdentification"},
    {"field": "references.patch", "importance": "High", "description": "Patch references", "cna_scorecard_category": "patchinfo"},
    
    # Non-measured fields (no cna_scorecard_category)
    {"field": "descriptions.english", "importance": "Medium", "description": "At least one English description"},
    {"field": "affected.vendor", "importance": "Medium", "description": "Vendor information in affected products"},
    {"field": "affected.product", "importance": "Medium", "description": "Product information in affected products"},
    {"field": "affected.versions", "importance": "Medium", "description": "Version information"},
    {"field": "containers.cna.title", "importance": "Medium", "description": "Brief title or headline"},
    {"field": "problemTypes.type", "importance": "Medium", "description": "Problem type classification"},
    {"field": "containers.cna.problemTypes", "importance": "High", "description": "Problem type information (CWE, etc.)"},
    
    # CVSS and metrics (non-measured - cvssV3_0, cvssV3_1, cvssV4 are measured above)
    {"field": "metrics.cvssV2_0", "importance": "Medium", "description": "CVSS v2.0 metrics"},
    {"field": "metrics.scenarios", "importance": "Medium", "description": "Metric scenarios"},
    {"field": "metrics.other", "importance": "Medium", "description": "Other metric formats"},
    {"field": "containers.cna.metrics", "importance": "High", "description": "Impact metrics (CVSS scores)"},
    
    # Reference types (non-measured - only patch/advisory are measured above)
    {"field": "references.advisory", "importance": "Medium", "description": "Advisory references"},
    {"field": "references.article", "importance": "Medium", "description": "Article references"},
    {"field": "references.report", "importance": "Medium", "description": "Report references"},
    {"field": "references.web", "importance": "Medium", "description": "Web references"},
    {"field": "references.mailing-list", "importance": "Medium", "description": "Mailing list references"},
    
    # Affected product details
    {"field": "affected.defaultStatus", "importance": "Medium", "description": "Default status for affected products"},
    {"field": "affected.modules", "importance": "Medium", "description": "Affected modules or components"},
    {"field": "affected.programFiles", "importance": "Medium", "description": "Affected program files"},
    {"field": "affected.programRoutines", "importance": "Medium", "description": "Affected functions or methods"},
    {"field": "affected.repo", "importance": "Medium", "description": "Source code repository URL"},
    
    # Additional CNA-provided content
    {"field": "containers.cna.impacts", "importance": "Medium", "description": "Impact descriptions"},
    {"field": "containers.cna.solutions", "importance": "Medium", "description": "Solutions and remediations"},
    {"field": "containers.cna.workarounds", "importance": "Medium", "description": "Workaround information"},
    {"field": "containers.cna.exploits", "importance": "Medium", "description": "Exploit information"},
    {"field": "containers.cna.timeline", "importance": "Medium", "description": "Vulnerability timeline"},
    {"field": "containers.cna.credits", "importance": "Medium", "description": "Credit information"},
    {"field": "containers.cna.source", "importance": "Medium", "description": "Source information"},
    {"field": "containers.cna.configurations", "importance": "Medium", "description": "Configuration requirements"},
    {"field": "containers.cna.tags", "importance": "Low", "description": "CNA-provided tags"},
    {"field": "containers.cna.datePublic", "importance": "Low", "description": "Date the vulnerability was disclosed publicly"},
    {"field": "containers.cna.dateAssigned", "importance": "Low", "description": "Date the CVE ID was assigned"},
    
    # Enhanced descriptions (matching deployed field names) - NOT measured by CNA ScoreCard
    {"field": "descriptions.multiple_languages", "importance": "Low", "description": "Multiple language descriptions"},
    {"field": "descriptions.supporting_media", "importance": "Low", "description": "Supporting media in descriptions"},
    
    # ADP Container (included in deployed version)
    {"field": "containers.adp", "importance": "Low", "description": "Authorized Data Publisher container"},
]

# Field list for completeness analysis
FIELD_LIST = [f["field"] for f in CANONICAL_FIELDS]

# Logging configuration
LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        },
        'detailed': {
            'format': '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d: %(message)s'
        }
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard'
        },
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': 'pipeline.log',
            'formatter': 'detailed'
        }
    },
    'loggers': {
        'cnascorecard': {
            'handlers': ['console', 'file'],
            'level': 'DEBUG',
            'propagate': False
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['console']
    }
}

def get_config() -> Dict[str, Any]:
    """Get complete configuration dictionary."""
    return {
        'directories': {
            'pipeline': str(PIPELINE_DIR),
            'project_root': str(PROJECT_ROOT),
            'cve_data': str(CVE_DATA_DIR),
            'web_data': str(WEB_DATA_DIR),
            'completeness': str(COMPLETENESS_DIR),
            'cna_data': str(CNA_DATA_DIR),
        },
        'files': {
            'rules': str(RULES_FILE),
            'cwe_ids': str(CWE_IDS_FILE),
            'cna_list': str(CNA_LIST_FILE),
        },
        'analysis': {
            'date_format': DATE_FORMAT,
            'period_months': ANALYSIS_PERIOD_MONTHS,
        },
        'fields': {
            'scorecard_mapping': CNA_SCORECARD_FIELDS,
            'canonical_fields': CANONICAL_FIELDS,
            'field_list': FIELD_LIST,
        },
        'logging': LOGGING_CONFIG,
    }
