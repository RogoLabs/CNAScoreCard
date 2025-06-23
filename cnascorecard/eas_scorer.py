#!/usr/bin/env python3
"""
Calculates the Enriched Actionability Score (EAS) for a given CVE record.

This script accepts a file path to a CVE JSON 5.1 record and prints a
JSON object to standard output containing the total EAS score and a
detailed breakdown.
"""

import json
import sys
import re
from typing import Dict, Any, List

# A small, hardcoded list of known exploit database domains.
KNOWN_EXPLOIT_DOMAINS = ['exploit-db.com', 'github.com']

def score_foundational_completeness(cna_container: Dict[str, Any]) -> int:
    """
    Calculates the Foundational Completeness score.

    Args:
        cna_container: The 'cna' container from the CVE record.

    Returns:
        The score for this category (0-30).
    """
    score = 0
    # Metric: Affected Product/Vendor (10 points)
    if 'affected' in cna_container and isinstance(cna_container['affected'], list):
        for affect in cna_container['affected']:
            vendor = affect.get('vendor')
            product = affect.get('product')
            if vendor and product and vendor != 'N/A' and product != 'N/A':
                score += 10
                break

    # Metric: Structured Version Info (15 points)
    if 'affected' in cna_container and isinstance(cna_container['affected'], list):
        for affect in cna_container['affected']:
            if 'versions' in affect and isinstance(affect['versions'], list):
                for version in affect['versions']:
                    if version.get('status') and (version.get('version') or version.get('lessThanOrEqual')):
                        score += 15
                        break
            if score >= 25:  # Optimization: if we already have vendor/product + version
                break

    # Metric: Clear Problem Description (5 points)
    if 'descriptions' in cna_container and isinstance(cna_container['descriptions'], list):
        if cna_container['descriptions'] and len(cna_container['descriptions'][0].get('value', '')) > 40:
            score += 5

    return score

def score_root_cause_analysis(cna_container: Dict[str, Any]) -> int:
    """
    Calculates the Root Cause Analysis score.

    Args:
        cna_container: The 'cna' container from the CVE record.

    Returns:
        The score for this category (0-20).
    """
    # Metric: CWE ID Provided (20 points)
    cwe_pattern = re.compile(r'^CWE-[1-9][0-9]*$')
    if 'problemTypes' in cna_container and isinstance(cna_container['problemTypes'], list):
        for pt in cna_container['problemTypes']:
            if 'descriptions' in pt and isinstance(pt['descriptions'], list):
                for desc in pt['descriptions']:
                    cwe_id = desc.get('cweId')
                    if cwe_id and cwe_pattern.match(cwe_id):
                        return 20
    return 0

def score_severity_context(cna_container: Dict[str, Any]) -> int:
    """
    Calculates the Severity & Impact Context score.

    Args:
        cna_container: The 'cna' container from the CVE record.

    Returns:
        The score for this category (0-25).
    """
    score = 0
    cvss_v4_metrics = None

    if 'metrics' in cna_container and isinstance(cna_container['metrics'], list):
        for metric in cna_container['metrics']:
            # Metric: CVSS v3.1/v4.0 Base Score (10 points)
            if 'cvssV3_1' in metric and metric['cvssV3_1'].get('vectorString'):
                score = max(score, 10)
            if 'cvssV4_0' in metric and metric['cvssV4_0'].get('vectorString'):
                score = max(score, 10)
                cvss_v4_metrics = metric['cvssV4_0']

    if cvss_v4_metrics:
        # Metric: CVSS v4.0 Threat Metrics (5 points)
        if cvss_v4_metrics.get('E') and cvss_v4_metrics.get('E') != 'X':
            score += 5

        # Metric: CVSS v4.0 Environmental/Supplemental (max 10 points)
        env_supp_keys = ['CR', 'IR', 'AR', 'S', 'A', 'RE', 'U', 'V']
        defined_metrics = 0
        for key in env_supp_keys:
            if cvss_v4_metrics.get(key) and cvss_v4_metrics.get(key) != 'X':
                defined_metrics += 1
        score += min(defined_metrics * 2, 10)

    return score

def score_actionable_intelligence(cna_container: Dict[str, Any]) -> int:
    """
    Calculates the Actionable Intelligence score.

    Args:
        cna_container: The 'cna' container from the CVE record.

    Returns:
        The score for this category (0-20).
    """
    score = 0
    has_exploit_info = False
    has_vex_info = False

    if 'references' in cna_container and isinstance(cna_container['references'], list):
        references = cna_container['references']

        # Metric: High-Quality References (max 12 points)
        score += min(len(references) * 4, 12)

        for ref in references:
            # Metric: Exploit/PoC Information (5 points)
            if not has_exploit_info:
                tags = ref.get('tags', [])
                if 'exploit' in tags or 'poc' in tags:
                    has_exploit_info = True
                elif 'url' in ref:
                    if any(domain in ref['url'] for domain in KNOWN_EXPLOIT_DOMAINS):
                        has_exploit_info = True

            # Metric: VEX Data Provided (3 points)
            if not has_vex_info and 'vex' in ref.get('tags', []):
                has_vex_info = True

    if has_exploit_info:
        score += 5
    
    if has_vex_info:
        score += 3

    return score

def score_data_format_precision(cna_container: Dict[str, Any]) -> int:
    """
    Calculates the Data Format & Precision score.

    Args:
        cna_container: The 'cna' container from the CVE record.

    Returns:
        The score for this category (0-5).
    """
    # Metric: CPE Usage (5 points)
    if 'affected' in cna_container and isinstance(cna_container['affected'], list):
        for affect in cna_container['affected']:
            if 'cpes' in affect and isinstance(affect['cpes'], list):
                for cpe in affect['cpes']:
                    if isinstance(cpe, str) and cpe.startswith('cpe:2.3:'):
                        return 5
    return 0

def calculate_eas(cve_record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Orchestrates the EAS calculation by calling helper for each metric category.

    Args:
        cve_record: A dictionary representing a single CVE record.

    Returns:
        A dictionary with the total score and a detailed breakdown.
    """
    cna_container = cve_record.get('containers', {}).get('cna', {})

    breakdown = {
        "foundationalCompleteness": score_foundational_completeness(cna_container),
        "rootCauseAnalysis": score_root_cause_analysis(cna_container),
        "severityAndImpactContext": score_severity_context(cna_container),
        "actionableIntelligence": score_actionable_intelligence(cna_container),
        "dataFormatAndPrecision": score_data_format_precision(cna_container)
    }

    total_score = sum(breakdown.values())

    result = {
        "cveId": cve_record.get('cveMetadata', {}).get('cveId', 'N/A'),
        "assigningCna": cve_record.get('cveMetadata', {}).get('assignerShortName', 'N/A'),
        "totalEasScore": total_score,
        "scoreBreakdown": breakdown
    }
    return result

def main():
    """
    Main execution block. Handles command-line arguments, file reading,
    and orchestrates the scoring process.
    """
    if len(sys.argv) != 2:
        print("Usage: python eas_scorer.py <path_to_cve_json_file>", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]
    try:
        with open(file_path, 'r') as f:
            cve_record = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found at '{file_path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in file '{file_path}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    if 'cveMetadata' not in cve_record or 'containers' not in cve_record:
        print("Error: JSON file is missing required top-level keys ('cveMetadata', 'containers')", file=sys.stderr)
        sys.exit(1)

    eas_results = calculate_eas(cve_record)
    print(json.dumps(eas_results, indent=2))

if __name__ == "__main__":
    main()
