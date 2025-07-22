"""
scoring.py: Compute category scores for each CVE record and aggregate for CNA.
"""
import os
import json

# Load SCORING_RULES from rules.json
RULES_PATH = os.path.join(os.path.dirname(__file__), 'rules.json')
with open(RULES_PATH, 'r') as f:
    SCORING_RULES = json.load(f)

# Load valid CWE IDs from cwe_ids.json
CWE_IDS_PATH = os.path.join(os.path.dirname(__file__), 'cwe_ids.json')
with open(CWE_IDS_PATH, 'r') as f:
    VALID_CWE_IDS = set(json.load(f))

def score_cve_record(cve):
    """
    Compute category-based score for a CVE record according to CNA Scorecard methodology.

    Categories and weights (max points):
    - Foundational Completeness (50): problemTypes, affected products, references, descriptions
    - Root Cause Analysis (15): valid CWE ID, specific CWE
    - Severity & Impact Context (15): CVSS v3/v4 metrics, valid CVSS vector string
    - Software Identification (10): valid CPE in affected
    - Patch Info (10): Patch/Vendor Advisory in references

    Returns dict with totalScore, scoreBreakdown, and assigningCna.
    """
    containers = cve.get("containers", {})
    cna = containers.get("cna", {})
    provider = cna.get("providerMetadata", {})
    assigning_cna = provider.get("shortName", "Unknown")

    foundational_score = _calculate_foundational_completeness(cve, cna)
    root_cause_score = _calculate_root_cause_analysis(cve, cna)
    severity_score = _calculate_severity_context(cve, cna)
    software_id_score = _calculate_software_identification(cve, cna)
    actionable_score = _calculate_actionable_intelligence(cve, cna)

    scoreBreakdown = {
        "foundationalCompleteness": foundational_score,
        "rootCauseAnalysis": root_cause_score,
        "severityAndImpactContext": severity_score,
        "softwareIdentification": software_id_score,
        "patchinfo": actionable_score
    }
    totalScore = sum(scoreBreakdown.values())

    cve_id = cve.get("cveId") or cve.get("cveMetadata", {}).get("cveId", "")
    date_published = cve.get("datePublished") or cve.get("cveMetadata", {}).get("datePublished", "")
    return {
        "cveId": cve_id,
        "datePublished": date_published,
        "assigningCna": assigning_cna,
        "totalScore": totalScore,
        "scoreBreakdown": scoreBreakdown
    }


def _calculate_foundational_completeness(cve, cna):
    rule = SCORING_RULES['foundationalCompleteness']
    criteria = rule['criteria']
    if all(bool(cna.get(field, [])) for field in criteria):
        return rule['weight']
    return 0

def _calculate_root_cause_analysis(cve, cna):
    rule = SCORING_RULES['rootCauseAnalysis']
    # Try cna['problemTypes'], then cve['containers']['cna']['problemTypes'], then cve['problemTypes']
    problem_types = (
        cna.get('problemTypes')
        or cve.get('containers', {}).get('cna', {}).get('problemTypes')
        or cve.get('problemTypes', [])
    )
    valid_cwe = False
    for pt in problem_types:
        for cwe in pt.get('descriptions', []):
            # Prefer cweId, fallback to value, then description
            cwe_id_field = cwe.get('cweId')
            cwe_val_field = cwe.get('value')
            cwe_desc_field = cwe.get('description')
            cwe_raw = cwe_id_field or cwe_val_field or cwe_desc_field
            if cwe_raw:
                if isinstance(cwe_raw, str) and cwe_raw.startswith('CWE-'):
                    cwe_num = cwe_raw[4:]
                else:
                    cwe_num = str(cwe_raw)
                if cwe_num in VALID_CWE_IDS:
                    valid_cwe = True
                    break
        if valid_cwe:
            break
    if valid_cwe:
        return rule['weight']
    return 0

def _calculate_severity_context(cve, cna):
    rule = SCORING_RULES['severityAndImpactContext']
    metrics = cna.get('metrics', [])
    has_cvss = any(
        ("cvssV4_0" in metric) or ("cvssV3_1" in metric) or ("cvssV3_0" in metric)
        for metric in metrics if isinstance(metric, dict)
    )
    valid_vector = any(
        ("cvssV4_0" in metric and metric["cvssV4_0"].get("vectorString")) or
        ("cvssV3_1" in metric and metric["cvssV3_1"].get("vectorString")) or
        ("cvssV3_0" in metric and metric["cvssV3_0"].get("vectorString"))
        for metric in metrics if isinstance(metric, dict)
    )
    if has_cvss and valid_vector:
        return rule['weight']
    return 0

def _calculate_software_identification(cve, cna):
    rule = SCORING_RULES['softwareIdentification']
    affected = cna.get('affected', [])
    has_cpe = any(
        product.get('cpes') and isinstance(product.get('cpes'), list) and len(product.get('cpes')) > 0
        for product in affected if isinstance(product, dict)
    )
    if has_cpe:
        return rule['weight']
    return 0

def _calculate_actionable_intelligence(cve, cna):
    rule = SCORING_RULES['patchinfo']
    references = cna.get('references', [])
    score = 0
    if references:
        # 5 points for Patch reference
        patch_refs = any(
            ref.get('tags') and any('patch' in str(tag).lower() for tag in ref.get('tags', []))
            for ref in references if isinstance(ref, dict)
        )
        if patch_refs:
            score += rule['partialPoints']['patchRef']
        
    return min(score, rule['weight'])
