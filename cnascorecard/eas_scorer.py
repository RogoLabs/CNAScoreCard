#!/usr/bin/env python3
"""
Enhanced Aggregate Scoring (EAS) system for CVE records.
Evaluates CVE quality across multiple dimensions.
"""

import re
import json
import sys
from typing import Dict, Any, List

# A small, hardcoded list of known exploit database domains.
KNOWN_EXPLOIT_DOMAINS = ['exploit-db.com']

class EnhancedAggregateScorer:
    """
    A class to calculate the Enhanced Aggregate Score (EAS) for a CVE record.
    """
    def __init__(self, cve_data: Dict[str, Any]):
        if not cve_data:
            raise ValueError("CVE data cannot be empty")
        self.cve_data = cve_data
        self.cna_container = self.cve_data.get('containers', {}).get('cna', {})

    def calculate_scores(self) -> Dict[str, Any]:
        """
        Calculate Enhanced Aggregate Score (EAS) for a CVE record.
        """
        # Extract basic metadata
        cve_id = self.cve_data.get('cveMetadata', {}).get('cveId', 'Unknown')
        assigning_cna = self.cve_data.get('cveMetadata', {}).get('assignerShortName', 'Unknown')
        date_published = self.cve_data.get('cveMetadata', {}).get('datePublished', '')

        # Calculate individual scores
        foundational_score = self._calculate_foundational_completeness()
        root_cause_score = self._calculate_root_cause_analysis()
        severity_score = self._calculate_severity_context()
        actionable_score = self._calculate_actionable_intelligence()
        format_score = self._calculate_data_format_precision()

        # Calculate total EAS score (simple sum)
        total_eas_score = (
            foundational_score +
            root_cause_score +
            severity_score +
            actionable_score +
            format_score
        )

        return {
            'cveId': cve_id,
            'assigningCna': assigning_cna,
            'datePublished': date_published,
            'totalEasScore': round(total_eas_score, 2),
            'scoreBreakdown': {
                'foundationalCompleteness': round(foundational_score, 2),
                'rootCauseAnalysis': round(root_cause_score, 2),
                'severityAndImpactContext': round(severity_score, 2),
                'actionableIntelligence': round(actionable_score, 2),
                'dataFormatAndPrecision': round(format_score, 2)
            }
        }

    def _calculate_foundational_completeness(self) -> int:
        """Calculate foundational completeness score (0-30)."""
        score = 0
        max_score = 30
        
        # Check for basic required fields
        if self.cna_container.get('descriptions'):
            descriptions = self.cna_container['descriptions']
            if isinstance(descriptions, list) and len(descriptions) > 0:
                # Check for English description
                has_english = any(d.get('lang') == 'en' for d in descriptions if isinstance(d, dict))
                if has_english:
                    score += 10
                    # Check description quality
                    en_desc = next((d.get('value', '') for d in descriptions if d.get('lang') == 'en'), '')
                    if len(en_desc) > 50:
                        score += 5
        
        # Check for affected products
        if self.cna_container.get('affected'):
            affected = self.cna_container['affected']
            if isinstance(affected, list) and len(affected) > 0:
                score += 10
                # Check for version information
                has_versions = any(
                    item.get('versions') for item in affected if isinstance(item, dict)
                )
                if has_versions:
                    score += 5
        
        return min(score, max_score)

    def _calculate_root_cause_analysis(self) -> int:
        """Calculate root cause analysis score (0-20)."""
        score = 0
        max_score = 20
        
        # Check problem types for technical detail
        problem_types = self.cna_container.get('problemTypes', [])
        if isinstance(problem_types, list):
            for pt in problem_types:
                if isinstance(pt, dict) and pt.get('descriptions'):
                    descriptions = pt['descriptions']
                    if isinstance(descriptions, list):
                        for desc in descriptions:
                            if isinstance(desc, dict):
                                cwe_id = desc.get('cweId', '')
                                if cwe_id and cwe_id.startswith('CWE-'):
                                    score = 20  # Full score for having CWE
                                    break
                    if score > 0:
                        break
        
        # Check descriptions for technical depth (additional points)
        descriptions = self.cna_container.get('descriptions', [])
        if isinstance(descriptions, list):
            for desc in descriptions:
                if isinstance(desc, dict) and desc.get('lang') == 'en':
                    text = desc.get('value', '').lower()
                    # Look for technical indicators (no additional points if already have CWE)
                    if score == 0:
                        technical_terms = [
                            'buffer overflow', 'sql injection', 'cross-site scripting', 'xss',
                            'authentication', 'authorization', 'memory', 'heap', 'stack',
                            'integer overflow', 'format string', 'race condition',
                            'privilege escalation', 'directory traversal', 'code injection'
                        ]
                        found_terms = sum(1 for term in technical_terms if term in text)
                        if found_terms > 0:
                            score = min(10, found_terms * 2)  # Up to 10 points for technical terms
                    break
        
        return min(score, max_score)

    def _calculate_severity_context(self) -> int:
        """Calculate severity and impact context score (0-25)."""
        score = 0
        max_score = 25
        
        # Check for CVSS metrics
        metrics = self.cna_container.get('metrics', [])
        if isinstance(metrics, list):
            for metric in metrics:
                if isinstance(metric, dict):
                    # Check for CVSS v3
                    if 'cvssV3_1' in metric or 'cvssV3_0' in metric:
                        cvss_data = metric.get('cvssV3_1') or metric.get('cvssV3_0')
                        if isinstance(cvss_data, dict):
                            if cvss_data.get('baseScore') is not None:
                                score += 15
                            if cvss_data.get('vectorString'):
                                score += 5
                            break
                    # Check for CVSS v2
                    elif 'cvssV2' in metric:
                        cvss_data = metric['cvssV2']
                        if isinstance(cvss_data, dict) and cvss_data.get('baseScore') is not None:
                            score += 10
                            break
        
        # Check descriptions for impact information
        descriptions = self.cna_container.get('descriptions', [])
        if isinstance(descriptions, list):
            for desc in descriptions:
                if isinstance(desc, dict) and desc.get('lang') == 'en':
                    text = desc.get('value', '').lower()
                    impact_terms = [
                        'remote code execution', 'denial of service', 'information disclosure',
                        'privilege escalation', 'data corruption', 'system compromise',
                        'arbitrary code', 'crash', 'hang', 'memory corruption'
                    ]
                    if any(term in text for term in impact_terms):
                        score += 5
                    break
        
        return min(score, max_score)

    def _calculate_actionable_intelligence(self) -> int:
        """Calculate actionable intelligence score (0-20)."""
        score = 0
        max_score = 20
        
        # Check for solution information
        solutions = self.cna_container.get('solutions', [])
        if isinstance(solutions, list) and len(solutions) > 0:
            score += 8
            # Check for detailed solutions
            for solution in solutions:
                if isinstance(solution, dict):
                    value = solution.get('value', '')
                    if len(value) > 100:
                        score += 4
                        break
        
        # Check references for actionable content
        references = self.cna_container.get('references', [])
        if isinstance(references, list):
            actionable_refs = 0
            for ref in references:
                if isinstance(ref, dict):
                    url = ref.get('url', '').lower()
                    name = ref.get('name', '').lower()
                    tags = ref.get('tags', [])
                    
                    # Look for patch/advisory references
                    if any(tag in ['Patch', 'Vendor Advisory', 'Mitigation'] for tag in tags):
                        actionable_refs += 1
                    elif any(term in url for term in ['patch', 'advisory', 'security', 'fix']):
                        actionable_refs += 1
                    elif any(term in name for term in ['patch', 'advisory', 'fix', 'update']):
                        actionable_refs += 1
            
            if actionable_refs > 0:
                score += min(6, actionable_refs * 3)
        
        # Check for workaround information
        workarounds = self.cna_container.get('workarounds', [])
        if isinstance(workarounds, list) and len(workarounds) > 0:
            score += 2
        
        return min(score, max_score)

    def _calculate_data_format_precision(self) -> int:
        """Calculate data format and precision score (0-5)."""
        score = 0
        max_score = 5
        
        # Check affected products structure
        affected = self.cna_container.get('affected', [])
        if isinstance(affected, list):
            for item in affected:
                if isinstance(item, dict):
                    # Check for vendor/product information
                    if item.get('vendor') and item.get('product'):
                        score += 1
                    
                    # Check for version information
                    versions = item.get('versions', [])
                    if isinstance(versions, list) and len(versions) > 0:
                        score += 1
                        # Check for detailed version info
                        for version in versions:
                            if isinstance(version, dict):
                                if version.get('version') and version.get('status'):
                                    score += 1
                                    break
                    break
        
        # Check for properly formatted problem types
        problem_types = self.cna_container.get('problemTypes', [])
        if isinstance(problem_types, list):
            for pt in problem_types:
                if isinstance(pt, dict) and pt.get('descriptions'):
                    descriptions = pt['descriptions']
                    if isinstance(descriptions, list):
                        for desc in descriptions:
                            if isinstance(desc, dict) and desc.get('type') and desc.get('description'):
                                score += 1
                                break
                    break
        
        # Check for language consistency
        descriptions = self.cna_container.get('descriptions', [])
        if isinstance(descriptions, list):
            for desc in descriptions:
                if isinstance(desc, dict) and desc.get('lang'):
                    score += 1
                    break
        
        return min(score, max_score)

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

    scorer = EnhancedAggregateScorer(cve_record)
    eas_results = scorer.calculate_scores()
    print(json.dumps(eas_results, indent=2))

if __name__ == "__main__":
    main()
