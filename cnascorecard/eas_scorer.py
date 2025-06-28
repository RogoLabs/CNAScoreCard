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
# Add cvss library for         # Impact/exploitation context (4 points)

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
    """Enhanced scorer that combines multiple scoring approaches for comprehensive CVE assessment."""
    
    # Updated vulnerability types based on CVE description analysis
    vuln_types = [
        'file inclusion', 'sql injection', 'access control', 'local file inclusion',
        'remote file inclusion', 'cross-site scripting', 'command injection', 
        'buffer overflow', 'sanitization', 'authentication bypass',
        'null pointer dereference', 'path traversal', 'improper validation',
        'xss', 'denial of service', 'out-of-bounds', 'code injection',
        'privilege escalation', 'xml external entity', 'double free',
        'use after free', 'race condition', 'integer overflow', 'format string',
        'heap overflow', 'stack overflow', 'type confusion', 'memory corruption',
        'deserialization', 'directory traversal', 'xxe', 'server-side request forgery',
        'ssrf', 'csrf', 'cross-site request forgery', 'remote code execution',
        'arbitrary code execution', 'prototype pollution', 'insecure deserialization',
        'ldap injection', 'xpath injection', 'template injection', 'header injection',
        'clickjacking', 'certificate validation', 'weak encryption', 'cryptographic',
        'resource exhaustion', 'infinite loop', 'zip slip', 'business logic',
        'improper input validation', 'missing authentication', 'weak authentication',
        'logic error'
    ]
    
    impact_terms = [
        'leads to', 'disclose', 'execute arbitrary', 'arbitrary code execution', 
        'remote attackers', 'authenticated attackers', 'allows', 'bypass',
        'can be exploited', 'remote code execution', 'unauthenticated attackers',
        'attackers can', 'results in', 'manipulate', 'obtain', 'compromise',
        'gain access', 'unauthorized access', 'enables', 'permits', 'facilitates',
        'triggers', 'may allow', 'could allow', 'escalate privileges', 'circumvent',
        'retrieve', 'expose', 'information disclosure', 'data exposure',
        'sensitive information', 'leak', 'reveal', 'crash', 'hang', 'freeze',
        'terminate', 'local attackers', 'malicious users', 'crafted',
        'specially crafted', 'malicious', 'attacker', 'exploitation',
        'exploitable', 'when processing', 'during processing', 'via the'
    ]
    
    tech_terms = [
        'argument', 'component', 'class', 'parameter', 'function', 'field',
        'via the', 'within the', 'plugin', 'in the', 'api', 'service',
        'endpoint', 'interface', 'handler', 'through the', 'buffer',
        'library', 'method', 'variable', 'property', 'object', 'instance',
        'request', 'response', 'header', 'cookie', 'session', 'module',
        'framework', 'driver', 'daemon', 'process', 'thread', 'parser',
        'processor', 'validator', 'serializer', 'deserializer', 'encoder',
        'decoder', 'protocol', 'socket', 'connection', 'channel', 'stream',
        'queue', 'when processing', 'during processing', 'while handling',
        'when parsing', 'during parsing', 'application', 'implementation',
        'configuration', 'initialization', 'authentication mechanism',
        'authorization mechanism', 'validation routine', 'sanitization'
    ]
    
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

        # Calculate total EAS score (simple sum)
        total_eas_score = (
            foundational_score +
            root_cause_score +
            software_identification_score +
            severity_score +
            actionable_score
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
            }
        }

    def _calculate_foundational_completeness(self) -> int:
        """Calculate foundational completeness score (0-32)."""
        score = 0
        max_score = 32
        
        # Check for basic required fields
        descriptions = self.cna_container.get('descriptions', [])
        has_english_desc = False
        if descriptions:
            # Find English description and evaluate quality (15 points max)
            english_desc = None
            for desc in descriptions:
                lang = desc.get('lang', '').lower()
                if lang in ['en', 'eng', 'english']:
                    english_desc = desc.get('value', '')
                    has_english_desc = True
                    break
            
            # Evaluate description quality (15 points max)
            if english_desc:
                quality_score = self._evaluate_description_quality(english_desc)
                score += quality_score
        
        # Add point for language tag correctness
        if has_english_desc:
            score += 1
        
        # Check for affected products (10 points)
        affected = self.cna_container.get('affected', [])
        if affected and len(affected) > 0:
            score += 10
            
            # Add point for structured data
            score += 1

            # Check for version information (5 points)
            for product in affected:
                versions = product.get('versions', [])
                if versions and any(v.get('version') or v.get('versionType') or v.get('status') for v in versions):
                    score += 5
                    break
        
        return min(score, max_score)
    
    def _evaluate_description_quality(self, description: str) -> int:
        """
        Evaluate the quality of a vulnerability description.
        Returns 0-15 points based on content depth and technical relevance.
        """
        if not description or len(description.strip()) < 20:
            return 0
        
        desc_lower = description.lower().strip()
        quality_score = 0
        
        # Basic length and structure check (3 points)
        if len(desc_lower) >= 50:
            quality_score += 1
        if len(desc_lower) >= 100:
            quality_score += 1
        if len(desc_lower) >= 200:
            quality_score += 1
        
        # Technical vulnerability indicators (4 points) - Enhanced with data-driven analysis
        vuln_types = [
            'buffer overflow', 'sql injection', 'xss', 'cross-site scripting',
            'privilege escalation', 'code injection', 'path traversal',
            'denial of service', 'memory corruption', 'use after free',
            'race condition', 'authentication bypass', 'authorization bypass',
            'deserialization', 'command injection', 'file inclusion',
            'directory traversal', 'format string', 'integer overflow',
            'xml external entity', 'xxe', 'server-side request forgery', 'ssrf',
            'csrf', 'cross-site request forgery', 'heap overflow', 'stack overflow',
            'double free', 'out-of-bounds', 'type confusion', 'null pointer dereference',
            'remote code execution', 'arbitrary code execution', 'local file inclusion',
            'remote file inclusion', 'prototype pollution', 'insecure deserialization',
            'ldap injection', 'xpath injection', 'template injection', 'header injection',
            'clickjacking', 'certificate validation', 'weak encryption', 'cryptographic',
            'resource exhaustion', 'infinite loop', 'zip slip', 'business logic',
            'improper validation', 'improper input validation', 'missing authentication',
            'weak authentication', 'access control', 'logic error'
        ]
        
        if any(vtype in desc_lower for vtype in vuln_types):
            quality_score += 2
        
        # Additional technical terms
        tech_terms = [
            'vulnerability', 'exploit', 'attack', 'malicious', 'crafted',
            'arbitrary code', 'remote', 'local', 'authenticated', 'unauthenticated'
        ]
        tech_matches = sum(1 for term in tech_terms if term in desc_lower)
        if tech_matches >= 2:
            quality_score += 1
        if tech_matches >= 4:
            quality_score += 1
        
        # Impact/exploitation context (4 points)
        impact_terms = [
            'allows', 'enables', 'leads to', 'can be exploited',
            'unauthorized access', 'execute', 'obtain', 'bypass',
            'gain access', 'escalate', 'compromise', 'manipulate'
        ]
        
        impact_matches = sum(1 for term in impact_terms if term in desc_lower)
        if impact_matches >= 1:
            quality_score += 1
        if impact_matches >= 2:
            quality_score += 1
        if impact_matches >= 3:
            quality_score += 2
        
        # Technical specificity (4 points)
        specific_terms = [
            'function', 'parameter', 'variable', 'field', 'method',
            'api', 'endpoint', 'when processing', 'via the', 'through the',
            'in the', 'module', 'component', 'library', 'parser'
        ]
        
        specific_matches = sum(1 for term in specific_terms if term in desc_lower)
        if specific_matches >= 1:
            quality_score += 1
        if specific_matches >= 3:
            quality_score += 1
        if specific_matches >= 5:
            quality_score += 2
        
        # Penalty for overly generic content
        generic_phrases = [
            'security issue', 'security problem', 'security flaw',
            'may allow', 'could allow', 'might allow', 'possible to',
            'vulnerability exists', 'security vulnerability', 'flaw exists',
            'weakness in', 'issue in', 'vulnerability in the',
            'issue has been identified', 'problem has been found',
            'potential vulnerability', 'security weakness',
            'it is possible', 'there is a vulnerability',
            'vulnerability was found', 'vulnerability was discovered', 'security bug'
        ]
        
        generic_count = sum(1 for phrase in generic_phrases if phrase in desc_lower)
        if generic_count >= 2 and len(desc_lower) < 100:
            quality_score = max(0, quality_score - 2)
        
        return min(quality_score, 15)
        vuln_keywords = [
            'buffer overflow', 'sql injection', 'cross-site scripting', 'xss',
            'remote code execution', 'rce', 'privilege escalation', 'authentication bypass',
            'path traversal', 'directory traversal', 'arbitrary file', 'code injection',
            'command injection', 'memory corruption', 'use after free', 'null pointer',
            'integer overflow', 'format string', 'race condition', 'deserialization',
            'xml external entity', 'xxe', 'server-side request forgery', 'ssrf',
            'csrf', 'cross-site request forgery', 'denial of service', 'dos',
            'heap overflow', 'stack overflow', 'double free', 'out-of-bounds',
            'type confusion', 'logic error', 'access control', 'improper validation',
            'improper input validation', 'missing authentication', 'weak encryption',
            'cryptographic', 'certificate validation', 'tls', 'ssl'
        ]
        
        if any(keyword in desc_lower for keyword in vuln_keywords):
            quality_score += 1
        
        # Impact or exploitation context (1 point)
        impact_keywords = [
            'allows', 'enables', 'leads to', 'results in', 'can be exploited',
            'may allow', 'could allow', 'permits', 'expose', 'disclose',
            'execute arbitrary', 'gain access', 'bypass', 'escalate',
            'compromise', 'unauthorized', 'malicious', 'attacker'
        ]
        
        if any(keyword in desc_lower for keyword in impact_keywords):
            quality_score += 1
        
        # Technical specificity (1 point)
        # Look for specific component, function, or technical details
        specific_indicators = [
            'function', 'method', 'parameter', 'header', 'field', 'variable',
            'endpoint', 'api', 'request', 'response', 'cookie', 'session',
            'component', 'module', 'library', 'framework', 'protocol',
            'when processing', 'during', 'while handling', 'in the', 'via the'
        ]
        
        if any(indicator in desc_lower for indicator in specific_indicators):
            quality_score += 1
        
        # Avoid generic/low-quality descriptions (penalty)
        generic_phrases = [
            'vulnerability exists', 'security issue', 'security vulnerability',
            'issue has been identified', 'problem has been found', 'flaw exists',
            'weakness in', 'issue in', 'vulnerability in the'
        ]
        
        # If description is mostly generic phrases and short, reduce score
        if len(desc_lower) < 100 and any(phrase in desc_lower for phrase in generic_phrases):
            generic_count = sum(1 for phrase in generic_phrases if phrase in desc_lower)
            if generic_count >= 2:  # Multiple generic phrases in short description
                quality_score = max(0, quality_score - 1)
        
        return min(quality_score, 5)

    def _calculate_root_cause_analysis(self) -> int:
        """Calculate root cause analysis score (0-11)."""
        score = 0
        max_score = 11
        
        # Check problem types for CWE information
        problem_types = self.cna_container.get('problemTypes', [])
        cwe_found = False
        cwe_valid = False
        if isinstance(problem_types, list):
            for pt in problem_types:
                if isinstance(pt, dict) and pt.get('descriptions'):
                    descriptions = pt['descriptions']
                    if isinstance(descriptions, list):
                        for desc in descriptions:
                            if isinstance(desc, dict):
                                cwe_id = desc.get('cweId', '')
                                if cwe_id and cwe_id.startswith('CWE-'):
                                    cwe_found = True
                                    # If CWE validator is available, validate the CWE
                                    if self.cwe_validator and self.cwe_validator.is_valid_cwe(cwe_id):
                                        # Valid CWE gets full credit
                                        score = 10
                                        cwe_valid = True
                                    elif self.cwe_validator:
                                        # Invalid CWE gets minimal credit
                                        score = max(score, 2)
                                        logger.warning(f"Invalid CWE found: {cwe_id}")
                                    else:
                                        # No validator available, assume valid for backward compatibility
                                        score = 10
                                        cwe_valid = True
                                    break
                    if score >= 10:
                        break
        
        # Add point for valid CWE format
        if cwe_found and cwe_valid:
            score += 1

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
        """Calculate software identification score (0-11)."""
        score = 0
        max_score = 11
        cpe_present = False
        cpe_valid = False
        # Check for CPE in affected products
        affected = self.cna_container.get('affected', [])
        if isinstance(affected, list):
            for item in affected:
                if isinstance(item, dict):
                    # Check for 'cpes' (CVE 5.1 format - plural)
                    cpes = item.get('cpes', [])
                    if cpes:
                        cpe_present = True
                    if isinstance(cpes, list) and len(cpes) > 0:
                        # Validate that at least one CPE is valid using cpe lib
                        if any(self._is_valid_cpe(cpe) for cpe in cpes):
                            score = 10
                            cpe_valid = True
                            break
                    # Check for 'cpe' (legacy format - singular)
                    cpe = item.get('cpe', [])
                    if cpe:
                        cpe_present = True
                    if isinstance(cpe, list) and len(cpe) > 0:
                        if any(self._is_valid_cpe(c) for c in cpe):
                            score = 10
                            cpe_valid = True
                            break
                    # Some CNAs use 'cpe23Uri' or similar single string format
                    cpe_uri = item.get('cpe23Uri', '')
                    if cpe_uri:
                        cpe_present = True
                    if cpe_uri and isinstance(cpe_uri, str) and self._is_valid_cpe(cpe_uri):
                        score = 10
                        cpe_valid = True
                        break
                    # Check for other potential CPE field names
                    for field_name in ['cpeId', 'cpe_name', 'platformId']:
                        cpe_value = item.get(field_name, '')
                        if cpe_value:
                            cpe_present = True
                        if cpe_value and isinstance(cpe_value, str) and self._is_valid_cpe(cpe_value):
                            score = 10
                            cpe_valid = True
                            break
                    # Check for platformIds array
                    platform_ids = item.get('platformIds', [])
                    if platform_ids:
                        cpe_present = True
                    if isinstance(platform_ids, list) and len(platform_ids) > 0:
                        if any(self._is_valid_cpe(pid) for pid in platform_ids):
                            score = 10
                            cpe_valid = True
                            break
                    if score == 10:
                        break
        
        if cpe_present and cpe_valid:
            score += 1

        return min(score, max_score)

    def _calculate_severity_context(self) -> int:
        """Calculate severity and impact context score (0-26), using cvss lib for vector validation."""
        score = 0
        max_score = 26
        metrics = self.cna_container.get('metrics', [])
        cvss_present = False
        cvss_valid = True
        if isinstance(metrics, list):
            for metric in metrics:
                if isinstance(metric, dict):
                    for key in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
                        if key in metric:
                            cvss_present = True
                            cvss_data = metric.get(key)
                            if isinstance(cvss_data, dict):
                                if cvss_data.get('baseScore') is not None:
                                    score += 15
                                else:
                                    cvss_valid = False
                                vector = cvss_data.get('vectorString')
                                if vector and self._is_valid_cvss_vector(vector):
                                    score += 5
                                else:
                                    cvss_valid = False
                                break
                    if 'cvssV2' in metric:
                        cvss_present = True
                        cvss_data = metric['cvssV2']
                        if isinstance(cvss_data, dict) and cvss_data.get('baseScore') is not None:
                            score += 10
                            vector = cvss_data.get('vectorString')
                            if vector and self._is_valid_cvss_vector(vector):
                                score += 2  # Optionally, partial credit for v2 vector
                            else:
                                cvss_valid = False
                            break
                        else:
                            cvss_valid = False
        
        # Add point for valid CVSS format
        if cvss_present and cvss_valid:
            score += 1

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
