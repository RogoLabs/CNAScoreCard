#!/usr/bin/env python3
"""
Enhanced Aggregate Scoring (EAS) system for CVE records.
Evaluates CVE quality across multiple dimensions.
"""

import re
import json
import sys
import os
import logging
from typing import Dict, Any, List, Set, Optional
# Add cvss library for CVSS vector validation
try:
    from cvss import CVSS3, CVSS2, CVSS4
except ImportError:
    CVSS3 = None
    CVSS2 = None
    CVSS4 = None
try:
    from cpe import CPE
except ImportError:
    CPE = None

# A small, hardcoded list of known exploit database domains.
KNOWN_EXPLOIT_DOMAINS = ['exploit-db.com']

logger = logging.getLogger(__name__)

class SimpleCWEValidator:
    """Simple CWE validator using a prebuilt set of valid CWE IDs from cwe_ids.json"""
    
    def __init__(self):
        """Initialize with a set of valid CWE IDs loaded from cwe_ids.json"""
        self.valid_cwes: Set[str] = set()
        self._load_valid_cwes()
    
    def _load_valid_cwes(self):
        """Load valid CWE IDs from cwe_ids.json file"""
        try:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            cwe_json_path = os.path.join(script_dir, "cwe_ids.json")
            if not os.path.exists(cwe_json_path):
                # Try parent directory
                cwe_json_path = os.path.join(os.path.dirname(script_dir), "cwe_ids.json")
            if os.path.exists(cwe_json_path):
                with open(cwe_json_path, 'r') as f:
                    cwe_list = json.load(f)
                    # Accept both string and int representations
                    self.valid_cwes = set(str(cwe) for cwe in cwe_list)
                logger.info(f"Loaded {len(self.valid_cwes)} valid CWE IDs from cwe_ids.json")
            else:
                logger.warning("cwe_ids.json not found, no valid CWE IDs loaded")
        except Exception as e:
            logger.warning(f"Error loading cwe_ids.json: {e}, no valid CWE IDs loaded")
    
    def is_valid_cwe(self, cwe_id: str) -> bool:
        """Check if a CWE ID is valid (simple lookup)"""
        if not cwe_id:
            return False
        # Extract just the number part
        match = re.search(r'(\d+)', str(cwe_id))
        if match:
            number = match.group(1)
            return number in self.valid_cwes
        return False

class EnhancedAggregateScorer:
    """
    A class to calculate the Enhanced Aggregate Score (EAS) for a CVE record.
    """
    def __init__(self, cve_data: Dict[str, Any]):
        if not cve_data:
            raise ValueError("CVE data cannot be empty")
        self.cve_data = cve_data
        self.cna_container = self.cve_data.get('containers', {}).get('cna', {})
        # Initialize CWE validator
        try:
            self.cwe_validator = SimpleCWEValidator()
        except Exception as e:
            logger.warning(f"Failed to initialize CWE validator: {e}")
            self.cwe_validator = None

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
        software_identification_score = self._calculate_software_identification()
        severity_score = self._calculate_severity_context()
        actionable_score = self._calculate_actionable_intelligence()
        format_score = self._calculate_data_format_precision()

        # Calculate total EAS score (simple sum)
        total_eas_score = (
            foundational_score +
            root_cause_score +
            software_identification_score +
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
                'softwareIdentification': round(software_identification_score, 2),
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
        """Calculate root cause analysis score (0-10)."""
        score = 0
        max_score = 10
        
        # Check problem types for CWE information
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
                                    # If CWE validator is available, validate the CWE
                                    if self.cwe_validator and self.cwe_validator.is_valid_cwe(cwe_id):
                                        # Valid CWE gets full credit
                                        score = 10
                                    elif self.cwe_validator:
                                        # Invalid CWE gets minimal credit
                                        score = max(score, 2)
                                        logger.warning(f"Invalid CWE found: {cwe_id}")
                                    else:
                                        # No validator available, assume valid for backward compatibility
                                        score = 10
                                    break
                    if score >= 10:
                        break
        
        # If no CWE found, check descriptions for technical depth
        if score == 0:
            descriptions = self.cna_container.get('descriptions', [])
            if isinstance(descriptions, list):
                for desc in descriptions:
                    if isinstance(desc, dict) and desc.get('lang') == 'en':
                        text = desc.get('value', '').lower()
                        # Look for technical indicators
                        technical_terms = [
                            'buffer overflow', 'sql injection', 'cross-site scripting', 'xss',
                            'authentication', 'authorization', 'memory', 'heap', 'stack',
                            'integer overflow', 'format string', 'race condition',
                            'privilege escalation', 'directory traversal', 'code injection'
                        ]
                        found_terms = sum(1 for term in technical_terms if term in text)
                        if found_terms > 0:
                            score = min(5, found_terms * 1)  # Up to 5 points for technical terms
                        break
        
        return min(score, max_score)

    def _calculate_software_identification(self) -> int:
        """Calculate software identification score (0-10)."""
        score = 0
        max_score = 10
        # Check for CPE in affected products
        affected = self.cna_container.get('affected', [])
        if isinstance(affected, list):
            for item in affected:
                if isinstance(item, dict):
                    # Check for 'cpes' (CVE 5.1 format - plural)
                    cpes = item.get('cpes', [])
                    if isinstance(cpes, list) and len(cpes) > 0:
                        # Validate that at least one CPE is valid using cpe lib
                        if any(self._is_valid_cpe(cpe) for cpe in cpes):
                            score = max_score
                            break
                    # Check for 'cpe' (legacy format - singular)
                    cpe = item.get('cpe', [])
                    if isinstance(cpe, list) and len(cpe) > 0:
                        if any(self._is_valid_cpe(c) for c in cpe):
                            score = max_score
                            break
                    # Some CNAs use 'cpe23Uri' or similar single string format
                    cpe_uri = item.get('cpe23Uri', '')
                    if cpe_uri and isinstance(cpe_uri, str) and self._is_valid_cpe(cpe_uri):
                        score = max_score
                        break
                    # Check for other potential CPE field names
                    for field_name in ['cpeId', 'cpe_name', 'platformId']:
                        cpe_value = item.get(field_name, '')
                        if cpe_value and isinstance(cpe_value, str) and self._is_valid_cpe(cpe_value):
                            score = max_score
                            break
                    # Check for platformIds array
                    platform_ids = item.get('platformIds', [])
                    if isinstance(platform_ids, list) and len(platform_ids) > 0:
                        if any(self._is_valid_cpe(pid) for pid in platform_ids):
                            score = max_score
                            break
                    if score == max_score:
                        break
        return min(score, max_score)

    def _is_valid_cvss_vector(self, vector_string: str) -> bool:
        """Validate CVSS vector string using the cvss library (supports v2, v3, v4)"""
        if not vector_string or not isinstance(vector_string, str):
            return False
        try:
            if vector_string.startswith('CVSS:3.') and CVSS3:
                CVSS3(vector_string)
                return True
            elif vector_string.startswith('CVSS:4.') and CVSS4:
                CVSS4(vector_string)
                return True
            elif vector_string.startswith('(') or vector_string.startswith('AV:'):
                # Some v2 vectors are in legacy format
                if CVSS2:
                    CVSS2(vector_string)
                    return True
            elif vector_string.startswith('CVSS:2.') and CVSS2:
                CVSS2(vector_string)
                return True
        except Exception:
            return False
        return False

    def _calculate_severity_context(self) -> int:
        """Calculate severity and impact context score (0-25), using cvss lib for vector validation."""
        score = 0
        max_score = 25
        metrics = self.cna_container.get('metrics', [])
        if isinstance(metrics, list):
            for metric in metrics:
                if isinstance(metric, dict):
                    for key in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
                        if key in metric:
                            cvss_data = metric.get(key)
                            if isinstance(cvss_data, dict):
                                if cvss_data.get('baseScore') is not None:
                                    score += 15
                                vector = cvss_data.get('vectorString')
                                if vector and self._is_valid_cvss_vector(vector):
                                    score += 5
                                break
                    if 'cvssV2' in metric:
                        cvss_data = metric['cvssV2']
                        if isinstance(cvss_data, dict) and cvss_data.get('baseScore') is not None:
                            score += 10
                            vector = cvss_data.get('vectorString')
                            if vector and self._is_valid_cvss_vector(vector):
                                score += 2  # Optionally, partial credit for v2 vector
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

    def _is_valid_cpe(self, cpe_string: str) -> bool:
        """Validate CPE string using the cpe library (supports CPE 2.2 and 2.3)"""
        if not cpe_string or not isinstance(cpe_string, str):
            return False
        if CPE is None:
            # Fallback: basic string check if cpe lib not available
            return cpe_string.startswith('cpe:')
        try:
            cpe_obj = CPE(cpe_string)
            # If parsing does not raise, consider valid
            return True
        except Exception:
            return False

    def _calculate_data_format_precision(self) -> int:
        """Calculate data format and precision score (0-5), using cvss lib for vector validation."""
        max_score = 5
        format_checks = []
        penalize = False
        
        # Check 1: CPE format in affected products
        has_valid_cpe = False
        affected = self.cna_container.get('affected', [])
        if isinstance(affected, list):
            for item in affected:
                if isinstance(item, dict):
                    # Check for 'cpes' (CVE 5.1 format - plural)
                    if 'cpes' in item:
                        cpes = item.get('cpes', [])
                        if isinstance(cpes, list) and len(cpes) > 0:
                            if any(self._is_valid_cpe(cpe) for cpe in cpes):
                                has_valid_cpe = True
                            else:
                                penalize = True
                    # Check for 'cpe' (legacy format - singular)
                    elif 'cpe' in item:
                        cpe = item.get('cpe', [])
                        if isinstance(cpe, list) and len(cpe) > 0:
                            if any(self._is_valid_cpe(c) for c in cpe):
                                has_valid_cpe = True
                            else:
                                penalize = True
                    # Check for other CPE field formats
                    for field_name in ['cpe23Uri', 'cpeId', 'cpe_name', 'platformId']:
                        if field_name in item:
                            cpe_value = item.get(field_name, '')
                            if cpe_value and isinstance(cpe_value, str):
                                if self._is_valid_cpe(cpe_value):
                                    has_valid_cpe = True
                                else:
                                    penalize = True
                    # Check for platformIds array
                    if 'platformIds' in item:
                        platform_ids = item.get('platformIds', [])
                        if isinstance(platform_ids, list) and len(platform_ids) > 0:
                            if any(self._is_valid_cpe(pid) for pid in platform_ids):
                                has_valid_cpe = True
                            else:
                                penalize = True
        format_checks.append(has_valid_cpe or not any(
            (isinstance(item, dict) and (
                'cpes' in item or 'cpe' in item or any(f in item for f in ['cpe23Uri', 'cpeId', 'cpe_name', 'platformId', 'platformIds'])
            )) for item in affected
        ))
        
        # Check 2: CVSS format in metrics (use cvss lib)
        has_valid_cvss = False
        metrics = self.cna_container.get('metrics', [])
        if isinstance(metrics, list):
            for metric in metrics:
                if isinstance(metric, dict):
                    for cvss_key in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2']:
                        if cvss_key in metric:
                            cvss_data = metric.get(cvss_key)
                            if isinstance(cvss_data, dict):
                                vector_string = cvss_data.get('vectorString')
                                if (cvss_data.get('baseScore') is not None and 
                                    vector_string and 
                                    isinstance(vector_string, str) and
                                    self._is_valid_cvss_vector(vector_string)):
                                    has_valid_cvss = True
                                else:
                                    penalize = True
        format_checks.append(has_valid_cvss or not metrics)
        
        # Check 3: CWE format in problem types
        has_valid_cwe = False
        problem_types = self.cna_container.get('problemTypes', [])
        if isinstance(problem_types, list):
            for pt in problem_types:
                if isinstance(pt, dict) and pt.get('descriptions'):
                    descriptions = pt['descriptions']
                    if isinstance(descriptions, list):
                        for desc in descriptions:
                            if isinstance(desc, dict):
                                if 'cweId' in desc:
                                    cwe_id = desc.get('cweId', '')
                                    # Valid CWE format: starts with 'CWE-' followed by numbers
                                    if (cwe_id and isinstance(cwe_id, str) and 
                                        cwe_id.startswith('CWE-') and 
                                        cwe_id[4:].isdigit()):
                                        if self.cwe_validator and self.cwe_validator.is_valid_cwe(cwe_id):
                                            has_valid_cwe = True
                                        elif not self.cwe_validator:
                                            has_valid_cwe = True
                                        else:
                                            penalize = True
                                    else:
                                        penalize = True
        format_checks.append(has_valid_cwe or not any(
            isinstance(pt, dict) and any(isinstance(desc, dict) and 'cweId' in desc for desc in pt.get('descriptions', []))
            for pt in problem_types
        ))
        
        # Check 4: Language consistency in descriptions
        has_language_tags = False
        descriptions = self.cna_container.get('descriptions', [])
        if isinstance(descriptions, list):
            for desc in descriptions:
                if isinstance(desc, dict) and 'lang' in desc:
                    if desc.get('lang'):
                        has_language_tags = True
                        break
                elif isinstance(desc, dict) and 'lang' in desc and not desc.get('lang'):
                    penalize = True
        format_checks.append(has_language_tags or not descriptions)
        
        # Check 5: Affected products structure
        has_structured_affected = False
        if isinstance(affected, list):
            for item in affected:
                if isinstance(item, dict):
                    if ('vendor' in item and not item.get('vendor')) or ('product' in item and not item.get('product')):
                        penalize = True
                    if item.get('vendor') and item.get('product'):
                        has_structured_affected = True
                        break
        format_checks.append(has_structured_affected or not affected)
        
        # Award full points only if ALL format checks pass and no penalize
        if all(format_checks) and not penalize:
            return max_score
        else:
            return 0

def calculate_eas(cve_data):
    """
    Convenience function to calculate the Enhanced Aggregate Score (EAS) for a CVE record.
    """
    scorer = EnhancedAggregateScorer(cve_data)
    return scorer.calculate_scores()

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
