#!/usr/bin/env python3
"""
Enhanced Aggregate Scoring (EAS) system for CVE records.
Evaluates CVE quality across multiple dimensions.
"""

import re
import json
import sys
import os
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Set, Optional
import logging

# A small, hardcoded list of known exploit database domains.
KNOWN_EXPLOIT_DOMAINS = ['exploit-db.com']

logger = logging.getLogger(__name__)

class SimpleCWEValidator:
    """Simple CWE validator using a prebuilt set of valid CWE IDs"""
    
    def __init__(self):
        """Initialize with a simple set of valid CWE IDs"""
        self.valid_cwes: Set[str] = set()
        self._load_valid_cwes()
    
    def _load_valid_cwes(self):
        """Load valid CWE IDs from XML file or use fallback list"""
        try:
            # Try to load from XML file
            script_dir = os.path.dirname(os.path.abspath(__file__))
            cwe_xml_path = os.path.join(script_dir, "cwec_v4.17.xml")
            if not os.path.exists(cwe_xml_path):
                # Try parent directory
                cwe_xml_path = os.path.join(os.path.dirname(script_dir), "cwec_v4.17.xml")
            
            if os.path.exists(cwe_xml_path):
                tree = ET.parse(cwe_xml_path)
                root = tree.getroot()
                
                # Find all weakness IDs - try with and without namespace
                for weakness in root.findall('.//{http://cwe.mitre.org/cwe-7}Weakness'):
                    cwe_id = weakness.get('ID')
                    if cwe_id and cwe_id.isdigit():
                        self.valid_cwes.add(cwe_id)
                
                # Fallback without namespace
                if not self.valid_cwes:
                    for weakness in root.findall('.//Weakness'):
                        cwe_id = weakness.get('ID')
                        if cwe_id and cwe_id.isdigit():
                            self.valid_cwes.add(cwe_id)
                
                logger.info(f"Loaded {len(self.valid_cwes)} valid CWE IDs from XML")
            else:
                # Use fallback list of common CWEs if XML not found
                self._use_fallback_cwes()
                logger.warning("CWE XML not found, using fallback list")
                
        except Exception as e:
            logger.warning(f"Error loading CWE XML: {e}, using fallback list")
            self._use_fallback_cwes()
    
    def _use_fallback_cwes(self):
        """Use a fallback list of common valid CWE IDs"""
        # Common CWEs from the official list - this covers most real-world usage
        common_cwes = [
            "20", "22", "78", "79", "89", "120", "125", "190", "200", "269", "284", "311", "326", 
            "352", "362", "400", "401", "416", "476", "502", "611", "613", "617", "639", "665", 
            "667", "672", "681", "682", "704", "732", "787", "798", "807", "862", "863", "918", 
            "922", "1021", "1022", "1035", "1076", "1188", "1220", "1236", "1274", "1275", "1321"
        ]
        self.valid_cwes = set(common_cwes)
        logger.info(f"Using fallback list of {len(self.valid_cwes)} common CWE IDs")
    
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
                        # Validate that at least one CPE looks valid
                        if any(cpe and isinstance(cpe, str) and cpe.startswith('cpe:') for cpe in cpes):
                            score = max_score
                            break
                    
                    # Check for 'cpe' (legacy format - singular)
                    cpe = item.get('cpe', [])
                    if isinstance(cpe, list) and len(cpe) > 0:
                        # Validate that at least one CPE looks valid
                        if any(c and isinstance(c, str) and c.startswith('cpe:') for c in cpe):
                            score = max_score
                            break
                    
                    # Some CNAs use 'cpe23Uri' or similar single string format
                    cpe_uri = item.get('cpe23Uri', '')
                    if cpe_uri and isinstance(cpe_uri, str) and cpe_uri.startswith('cpe:'):
                        score = max_score
                        break
                    
                    # Check for other potential CPE field names
                    for field_name in ['cpeId', 'cpe_name', 'platformId']:
                        cpe_value = item.get(field_name, '')
                        if cpe_value and isinstance(cpe_value, str) and cpe_value.startswith('cpe:'):
                            score = max_score
                            break
                    
                    # Check for platformIds array
                    platform_ids = item.get('platformIds', [])
                    if isinstance(platform_ids, list) and len(platform_ids) > 0:
                        if any(pid and isinstance(pid, str) and pid.startswith('cpe:') for pid in platform_ids):
                            score = max_score
                            break
                    
                    if score == max_score:
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
                    # Check for CVSS v4, v3.1, v3.0
                    if 'cvssV4_0' in metric or 'cvssV3_1' in metric or 'cvssV3_0' in metric:
                        cvss_data = metric.get('cvssV4_0') or metric.get('cvssV3_1') or metric.get('cvssV3_0')
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
        max_score = 5
        format_checks = []
        
        # Check 1: CPE format in affected products
        has_valid_cpe = False
        affected = self.cna_container.get('affected', [])
        if isinstance(affected, list):
            for item in affected:
                if isinstance(item, dict):
                    # Check for 'cpes' (CVE 5.1 format - plural)
                    cpes = item.get('cpes', [])
                    if isinstance(cpes, list) and len(cpes) > 0:
                        if any(cpe and isinstance(cpe, str) and cpe.startswith('cpe:') for cpe in cpes):
                            has_valid_cpe = True
                            break
                    
                    # Check for 'cpe' (legacy format - singular)
                    cpe = item.get('cpe', [])
                    if isinstance(cpe, list) and len(cpe) > 0:
                        if any(c and isinstance(c, str) and c.startswith('cpe:') for c in cpe):
                            has_valid_cpe = True
                            break
                    
                    # Check for other CPE field formats
                    for field_name in ['cpe23Uri', 'cpeId', 'cpe_name', 'platformId']:
                        cpe_value = item.get(field_name, '')
                        if cpe_value and isinstance(cpe_value, str) and cpe_value.startswith('cpe:'):
                            has_valid_cpe = True
                            break
                    
                    # Check for platformIds array
                    platform_ids = item.get('platformIds', [])
                    if isinstance(platform_ids, list) and len(platform_ids) > 0:
                        if any(pid and isinstance(pid, str) and pid.startswith('cpe:') for pid in platform_ids):
                            has_valid_cpe = True
                            break
                    
                    if has_valid_cpe:
                        break
        format_checks.append(has_valid_cpe)
        
        # Check 2: CVSS format in metrics
        has_valid_cvss = False
        metrics = self.cna_container.get('metrics', [])
        if isinstance(metrics, list):
            for metric in metrics:
                if isinstance(metric, dict):
                    # Check for CVSS v4, v3.1, v3.0
                    if 'cvssV4_0' in metric or 'cvssV3_1' in metric or 'cvssV3_0' in metric:
                        cvss_data = metric.get('cvssV4_0') or metric.get('cvssV3_1') or metric.get('cvssV3_0')
                        if isinstance(cvss_data, dict):
                            # Must have both baseScore and vectorString for proper format
                            vector_string = cvss_data.get('vectorString')
                            if (cvss_data.get('baseScore') is not None and 
                                vector_string and 
                                isinstance(vector_string, str) and
                                len(vector_string) > 0):
                                has_valid_cvss = True
                                break
                    # Check for CVSS v2 (less strict as it's older)
                    elif 'cvssV2' in metric:
                        cvss_data = metric['cvssV2']
                        if isinstance(cvss_data, dict) and cvss_data.get('baseScore') is not None:
                            has_valid_cvss = True
                            break
        format_checks.append(has_valid_cvss)
        
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
                                cwe_id = desc.get('cweId', '')
                                # Valid CWE format: starts with 'CWE-' followed by numbers
                                if (cwe_id and isinstance(cwe_id, str) and 
                                    cwe_id.startswith('CWE-') and 
                                    cwe_id[4:].isdigit()):
                                    # Additional validation if CWE validator is available
                                    if self.cwe_validator and self.cwe_validator.is_valid_cwe(cwe_id):
                                        has_valid_cwe = True
                                        break
                                    elif not self.cwe_validator:
                                        # Basic format check only
                                        has_valid_cwe = True
                                        break
                    if has_valid_cwe:
                        break
        format_checks.append(has_valid_cwe)
        
        # Check 4: Language consistency in descriptions
        has_language_tags = False
        descriptions = self.cna_container.get('descriptions', [])
        if isinstance(descriptions, list):
            for desc in descriptions:
                if isinstance(desc, dict) and desc.get('lang'):
                    has_language_tags = True
                    break
        format_checks.append(has_language_tags)
        
        # Check 5: Affected products structure
        has_structured_affected = False
        if isinstance(affected, list):
            for item in affected:
                if isinstance(item, dict):
                    # Check for basic vendor/product structure
                    if item.get('vendor') and item.get('product'):
                        has_structured_affected = True
                        break
        format_checks.append(has_structured_affected)
        
        # Award full points only if ALL format checks pass
        # This ensures high-quality, well-structured CVE records get the full score
        if all(format_checks):
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
