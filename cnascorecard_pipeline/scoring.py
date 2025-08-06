"""
scoring.py: Compute category scores for each CVE record according to CNA Scorecard methodology.

This module provides functions to score individual CVE records based on completeness
of key data fields across five categories: foundational completeness, root cause analysis,
severity & impact context, software identification, and patch information.
"""
import logging
from typing import Dict, Any, Optional, List

from config import ScoringConfig
from utils import extract_cna_short_name, format_date_string

# Initialize logging and configuration
logger = logging.getLogger('cnascorecard.scoring')
scoring_config = ScoringConfig()

def score_cve_record(cve: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute category-based score for a CVE record according to CNA Scorecard methodology.

    Categories and weights (max points):
    - Foundational Completeness (50): problemTypes, affected products, references, descriptions
    - Root Cause Analysis (15): valid CWE ID, specific CWE
    - Severity & Impact Context (15): CVSS v3/v4 metrics, valid CVSS vector string
    - Software Identification (10): valid CPE in affected
    - Patch Info (10): Patch/Vendor Advisory in references

    Args:
        cve: CVE record dictionary containing vulnerability data

    Returns:
        Dictionary containing:
        - cveId: CVE identifier
        - datePublished: Publication date
        - assigningCna: CNA that assigned the CVE
        - totalScore: Sum of all category scores
        - scoreBreakdown: Individual category scores
    """
    try:
        containers = cve.get("containers", {})
        cna = containers.get("cna", {})
        
        # Extract CNA information
        assigning_cna = extract_cna_short_name(cve) or "Unknown"
        
        # Calculate category scores
        foundational_score = _calculate_foundational_completeness(cve, cna)
        root_cause_score = _calculate_root_cause_analysis(cve, cna)
        severity_score = _calculate_severity_context(cve, cna)
        software_id_score = _calculate_software_identification(cve, cna)
        actionable_score = _calculate_actionable_intelligence(cve, cna)

        score_breakdown = {
            "foundationalCompleteness": foundational_score,
            "rootCauseAnalysis": root_cause_score,
            "severityAndImpactContext": severity_score,
            "softwareIdentification": software_id_score,
            "patchinfo": actionable_score
        }
        total_score = sum(score_breakdown.values())

        # Extract CVE metadata
        cve_id = cve.get("cveId") or cve.get("cveMetadata", {}).get("cveId", "")
        date_published = cve.get("datePublished") or cve.get("cveMetadata", {}).get("datePublished", "")
        
        result = {
            "cveId": cve_id,
            "datePublished": format_date_string(date_published),
            "assigningCna": assigning_cna,
            "totalScore": total_score,
            "scoreBreakdown": score_breakdown
        }
        
        logger.debug(f"Scored CVE {cve_id}: {total_score}/100 points (CNA: {assigning_cna})")
        return result
        
    except Exception as e:
        cve_id = cve.get("cveId", "unknown")
        logger.error(f"Error scoring CVE {cve_id}: {e}")
        # Return zero score for failed records
        return {
            "cveId": cve_id,
            "datePublished": "",
            "assigningCna": "Unknown",
            "totalScore": 0,
            "scoreBreakdown": {
                "foundationalCompleteness": 0,
                "rootCauseAnalysis": 0,
                "severityAndImpactContext": 0,
                "softwareIdentification": 0,
                "patchinfo": 0
            }
        }


def _calculate_foundational_completeness(cve: Dict[str, Any], cna: Dict[str, Any]) -> int:
    """
    Calculate foundational completeness score based on presence of core fields.
    
    Args:
        cve: Full CVE record
        cna: CNA container from CVE record
        
    Returns:
        Score for foundational completeness (0 or weight value)
    """
    rule = scoring_config.rules['foundationalCompleteness']
    criteria = rule['criteria']
    
    # Check if all required fields are present and non-empty
    has_all_fields = all(bool(cna.get(field, [])) for field in criteria)
    
    score = rule['weight'] if has_all_fields else 0
    logger.debug(f"Foundational completeness: {score}/{rule['weight']} (criteria: {criteria})")
    
    return score

def _calculate_root_cause_analysis(cve: Dict[str, Any], cna: Dict[str, Any]) -> int:
    """
    Calculate root cause analysis score based on presence of valid CWE identifiers.
    
    Args:
        cve: Full CVE record
        cna: CNA container from CVE record
        
    Returns:
        Score for root cause analysis (0 or weight value)
    """
    rule = scoring_config.rules['rootCauseAnalysis']
    
    # Try multiple locations for problem types
    problem_types = (
        cna.get('problemTypes')
        or cve.get('containers', {}).get('cna', {}).get('problemTypes')
        or cve.get('problemTypes', [])
    )
    
    valid_cwe_found = _find_valid_cwe(problem_types)
    score = rule['weight'] if valid_cwe_found else 0
    
    logger.debug(f"Root cause analysis: {score}/{rule['weight']} (valid CWE: {valid_cwe_found})")
    return score


def _find_valid_cwe(problem_types: List[Dict[str, Any]]) -> bool:
    """
    Search for valid CWE identifiers in problem types.
    
    Args:
        problem_types: List of problem type dictionaries
        
    Returns:
        True if valid CWE found, False otherwise
    """
    if not problem_types:
        return False
        
    import re
    cwe_pattern = re.compile(r'CWE-\d+', re.IGNORECASE)
        
    for pt in problem_types:
        if not isinstance(pt, dict):
            continue
            
        for cwe in pt.get('descriptions', []):
            if not isinstance(cwe, dict):
                continue
                
            # Check for explicit cweId field first (existing logic)
            if "cweId" in cwe:
                cwe_raw = cwe.get('cweId')
                if cwe_raw and _is_valid_cwe_id(str(cwe_raw)):
                    return True
            
            # Check for CWE ID embedded in description text (new logic)
            desc_text = cwe.get('description', '')
            if desc_text:
                cwe_match = cwe_pattern.search(desc_text)
                if cwe_match:
                    extracted_cwe = cwe_match.group(0)
                    if _is_valid_cwe_id(extracted_cwe):
                        return True
            
            # Fallback to value field
            cwe_raw = cwe.get('value')
            if cwe_raw and _is_valid_cwe_id(str(cwe_raw)):
                return True
                
    return False


def _is_valid_cwe_id(cwe_raw: str) -> bool:
    """
    Check if a CWE identifier is valid.
    
    Args:
        cwe_raw: Raw CWE identifier string
        
    Returns:
        True if valid CWE ID, False otherwise
    """
    if not cwe_raw:
        return False
        
    # Extract numeric part from CWE-XXX format
    if cwe_raw.startswith('CWE-'):
        cwe_num = cwe_raw[4:]
    else:
        cwe_num = cwe_raw
        
    return cwe_num in scoring_config.valid_cwe_ids

def _calculate_severity_context(cve: Dict[str, Any], cna: Dict[str, Any]) -> int:
    """
    Calculate severity and impact context score based on CVSS metrics.
    
    Args:
        cve: Full CVE record
        cna: CNA container from CVE record
        
    Returns:
        Score for severity and impact context (0 or weight value)
    """
    rule = scoring_config.rules['severityAndImpactContext']
    metrics = cna.get('metrics', [])
    
    if not isinstance(metrics, list):
        logger.debug("Severity context: 0 (no metrics list found)")
        return 0
    
    has_cvss = _has_cvss_metrics(metrics)
    valid_vector = _has_valid_cvss_vector(metrics)
    
    score = rule['weight'] if (has_cvss and valid_vector) else 0
    logger.debug(f"Severity context: {score}/{rule['weight']} (CVSS: {has_cvss}, vector: {valid_vector})")
    
    return score


def _has_cvss_metrics(metrics: List[Dict[str, Any]]) -> bool:
    """
    Check if metrics contain CVSS data.
    
    Args:
        metrics: List of metric dictionaries
        
    Returns:
        True if CVSS metrics found, False otherwise
    """
    cvss_versions = ["cvssV4_0", "cvssV3_1", "cvssV3_0"]
    
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
            
        if any(version in metric for version in cvss_versions):
            return True
            
    return False


def _has_valid_cvss_vector(metrics: List[Dict[str, Any]]) -> bool:
    """
    Check if metrics contain valid CVSS vector strings.
    
    Args:
        metrics: List of metric dictionaries
        
    Returns:
        True if valid vector string found, False otherwise
    """
    cvss_versions = ["cvssV4_0", "cvssV3_1", "cvssV3_0"]
    
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
            
        for version in cvss_versions:
            if version in metric:
                cvss_data = metric[version]
                if isinstance(cvss_data, dict) and cvss_data.get("vectorString"):
                    return True
                    
    return False

def _calculate_software_identification(cve: Dict[str, Any], cna: Dict[str, Any]) -> int:
    """
    Calculate software identification score based on presence of CPE identifiers.
    
    Args:
        cve: Full CVE record
        cna: CNA container from CVE record
        
    Returns:
        Score for software identification (0 or weight value)
    """
    rule = scoring_config.rules['softwareIdentification']
    affected = cna.get('affected', [])
    
    if not isinstance(affected, list):
        logger.debug("Software identification: 0 (no affected products list)")
        return 0
    
    has_cpe = _has_cpe_identifiers(affected)
    score = rule['weight'] if has_cpe else 0
    
    logger.debug(f"Software identification: {score}/{rule['weight']} (CPE found: {has_cpe})")
    return score


def _has_cpe_identifiers(affected: List[Dict[str, Any]]) -> bool:
    """
    Check if affected products contain CPE identifiers.
    
    Args:
        affected: List of affected product dictionaries
        
    Returns:
        True if CPE identifiers found, False otherwise
    """
    for product in affected:
        if not isinstance(product, dict):
            continue
            
        cpes = product.get('cpes')
        if isinstance(cpes, list) and len(cpes) > 0:
            return True
            
    return False

def _calculate_actionable_intelligence(cve: Dict[str, Any], cna: Dict[str, Any]) -> int:
    """
    Calculate actionable intelligence score based on presence of patch references.
    
    Args:
        cve: Full CVE record
        cna: CNA container from CVE record
        
    Returns:
        Score for actionable intelligence/patch info (0 or weight value)
    """
    rule = scoring_config.rules['patchinfo']
    references = cna.get('references', [])
    
    if not isinstance(references, list):
        logger.debug("Actionable intelligence: 0 (no references list)")
        return 0
    
    has_patch_ref = _has_patch_references(references)
    score = rule['weight'] if has_patch_ref else 0
    
    logger.debug(f"Actionable intelligence: {score}/{rule['weight']} (patch ref: {has_patch_ref})")
    return score


def _has_patch_references(references: List[Dict[str, Any]]) -> bool:
    """
    Check if references contain patch-related tags.
    
    Args:
        references: List of reference dictionaries
        
    Returns:
        True if patch references found, False otherwise
    """
    for ref in references:
        if not isinstance(ref, dict):
            continue
            
        tags = ref.get('tags', [])
        if not isinstance(tags, list):
            continue
            
        # Check for patch-related tags (case-insensitive)
        for tag in tags:
            if isinstance(tag, str) and 'patch' in tag.lower():
                return True
                
    return False


def score_multiple_cves(cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Score multiple CVE records with progress tracking.
    
    Args:
        cves: List of CVE record dictionaries
        
    Returns:
        List of scored CVE records
    """
    from utils import ProgressTracker
    
    if not cves:
        logger.warning("No CVEs provided for scoring")
        return []
    
    logger.info(f"Starting to score {len(cves)} CVE records")
    progress = ProgressTracker(len(cves), "Scoring CVEs")
    
    scored_cves = []
    for cve in cves:
        try:
            scored_cve = score_cve_record(cve)
            scored_cves.append(scored_cve)
        except Exception as e:
            cve_id = cve.get("cveId", "unknown")
            logger.error(f"Failed to score CVE {cve_id}: {e}")
            continue
        finally:
            progress.update()
    
    progress.finish()
    logger.info(f"Successfully scored {len(scored_cves)} out of {len(cves)} CVE records")
    
    return scored_cves
