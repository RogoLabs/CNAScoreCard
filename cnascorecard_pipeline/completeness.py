"""
completeness.py: Calculate field utilization/completeness for all schema fields
using a robust, schema-driven approach with full parity to the V.01 analyzer.
"""
from collections import defaultdict
from typing import Dict, Any, List

def _get_schema_fields() -> Dict[str, Dict]:
    """Defines the key CVE schema fields for completeness analysis, matching the legacy field insights page."""
    return {
        # Auto-added fields (now included for full parity)
        "dataType": {"path": ["dataType"]},
        "dataVersion": {"path": ["dataVersion"]},
        "cveMetadata.cveId": {"path": ["cveMetadata", "cveId"]},
        "cveMetadata.assignerOrgId": {"path": ["cveMetadata", "assignerOrgId"]},
        "cveMetadata.state": {"path": ["cveMetadata", "state"]},
        "containers.cna.providerMetadata": {"path": ["containers", "cna", "providerMetadata"]},
        "cveMetadata.assignerShortName": {"path": ["cveMetadata", "assignerShortName"]},
        "cveMetadata.dateUpdated": {"path": ["cveMetadata", "dateUpdated"]},
        "cveMetadata.datePublished": {"path": ["cveMetadata", "datePublished"]},
        "cveMetadata.dateReserved": {"path": ["cveMetadata", "dateReserved"]},

        # CVE Metadata
        "cveMetadata.serial": {"path": ["cveMetadata", "serial"]},

        # CNA Container fields
        "containers.cna.title": {"path": ["containers", "cna", "title"]},
        "containers.cna.descriptions": {"path": ["containers", "cna", "descriptions"]},
        "containers.cna.affected": {"path": ["containers", "cna", "affected"]},
        "containers.cna.references": {"path": ["containers", "cna", "references"]},
        "containers.cna.problemTypes": {"path": ["containers", "cna", "problemTypes"]},
        "containers.cna.metrics": {"path": ["containers", "cna", "metrics"]},
        "containers.cna.impacts": {"path": ["containers", "cna", "impacts"]},
        "containers.cna.configurations": {"path": ["containers", "cna", "configurations"]},
        "containers.cna.workarounds": {"path": ["containers", "cna", "workarounds"]},
        "containers.cna.solutions": {"path": ["containers", "cna", "solutions"]},
        "containers.cna.exploits": {"path": ["containers", "cna", "exploits"]},
        "containers.cna.dateAssigned": {"path": ["containers", "cna", "dateAssigned"]},
        "containers.cna.datePublic": {"path": ["containers", "cna", "datePublic"]},
        "containers.cna.timeline": {"path": ["containers", "cna", "timeline"]},
        "containers.cna.credits": {"path": ["containers", "cna", "credits"]},
        "containers.cna.source": {"path": ["containers", "cna", "source"]},
        "containers.cna.tags": {"path": ["containers", "cna", "tags"]},
        "containers.cna.taxonomyMappings": {"path": ["containers", "cna", "taxonomyMappings"]},
        "containers.cna.cpeApplicability": {"path": ["containers", "cna", "cpeApplicability"]},
        # ADP Container
        "containers.adp": {"path": ["containers", "adp"]},
        # Descriptions
        "descriptions.english": {"path": ["containers", "cna", "descriptions"], "check": "english_description"},
        "descriptions.multiple_languages": {"path": ["containers", "cna", "descriptions"], "check": "multiple_languages"},
        "descriptions.supporting_media": {"path": ["containers", "cna", "descriptions"], "check": "supporting_media"},
        # Affected
        "affected.vendor": {"path": ["containers", "cna", "affected"], "check": "has_vendor"},
        "affected.product": {"path": ["containers", "cna", "affected"], "check": "has_product"},
        "affected.versions": {"path": ["containers", "cna", "affected"], "check": "has_versions"},
        "affected.defaultStatus": {"path": ["containers", "cna", "affected"], "check": "has_default_status"},
        "affected.cpes": {"path": ["containers", "cna", "affected"], "check": "has_cpes"},
        "affected.modules": {"path": ["containers", "cna", "affected"], "check": "has_modules"},
        "affected.programFiles": {"path": ["containers", "cna", "affected"], "check": "has_program_files"},
        "affected.programRoutines": {"path": ["containers", "cna", "affected"], "check": "has_program_routines"},
        "affected.platforms": {"path": ["containers", "cna", "affected"], "check": "has_platforms"},
        "affected.repo": {"path": ["containers", "cna", "affected"], "check": "has_repo"},
        # ProblemTypes
        "problemTypes.cwe": {"path": ["containers", "cna", "problemTypes"], "check": "has_cwe"},
        "problemTypes.type": {"path": ["containers", "cna", "problemTypes"], "check": "has_type"},
        "problemTypes.references": {"path": ["containers", "cna", "problemTypes"], "check": "has_pt_references"},
        # References
        "references.advisory": {"path": ["containers", "cna", "references"], "check": "has_advisory_ref"},
        "references.patch": {"path": ["containers", "cna", "references"], "check": "has_patch_ref"},
        "references.exploit": {"path": ["containers", "cna", "references"], "check": "has_exploit_ref"},
        "references.technical": {"path": ["containers", "cna", "references"], "check": "has_technical_ref"},
        "references.vendor": {"path": ["containers", "cna", "references"], "check": "has_vendor_ref"},
        "references.named": {"path": ["containers", "cna", "references"], "check": "has_named_ref"},
        # Metrics
        "metrics.cvssV4": {"path": ["containers", "cna", "metrics"], "check": "has_cvss_v4"},
        "metrics.cvssV3_1": {"path": ["containers", "cna", "metrics"], "check": "has_cvss_v3_1"},
        "metrics.cvssV3_0": {"path": ["containers", "cna", "metrics"], "check": "has_cvss_v3_0"},
        "metrics.cvssV2": {"path": ["containers", "cna", "metrics"], "check": "has_cvss_v2"},
        "metrics.other": {"path": ["containers", "cna", "metrics"], "check": "has_other_metrics"},
        "metrics.scenarios": {"path": ["containers", "cna", "metrics"], "check": "has_scenarios"},
    }

def _get_nested_value(data: Dict[str, Any], path: List[str]) -> Any:
    current = data
    for key in path:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current

def _custom_check(data: Any, check_type: str) -> bool:
    """Custom check logic ported from legacy completeness_analyzer.py for 100% parity."""
    if not data:
        return False

    # Descriptions
    if check_type == "english_description":
        if isinstance(data, list):
            return any(desc.get("lang", "").lower().startswith("en") for desc in data if isinstance(desc, dict))
        return False
    if check_type == "multiple_languages":
        if isinstance(data, list):
            languages = set(desc.get("lang", "") for desc in data if isinstance(desc, dict))
            return len(languages) > 1
        return False
    if check_type == "supporting_media":
        if isinstance(data, list):
            return any(desc.get("media") for desc in data if isinstance(desc, dict))
        return False

    # Affected
    if check_type == "has_vendor":
        if isinstance(data, list):
            return any("vendor" in item for item in data if isinstance(item, dict))
        return False
    if check_type == "has_product":
        if isinstance(data, list):
            return any("product" in item for item in data if isinstance(item, dict))
        return False
    if check_type == "has_versions":
        if isinstance(data, list):
            return any(item.get("versions") for item in data if isinstance(item, dict))
        return False
    if check_type == "has_default_status":
        if isinstance(data, list):
            return any("defaultStatus" in item for item in data if isinstance(item, dict))
        return False
    if check_type == "has_cpes":
        if isinstance(data, list):
            return any(item.get("cpes") for item in data if isinstance(item, dict))
        return False
    if check_type == "has_modules":
        if isinstance(data, list):
            return any(item.get("modules") for item in data if isinstance(item, dict))
        return False
    if check_type == "has_program_files":
        if isinstance(data, list):
            return any(item.get("programFiles") for item in data if isinstance(item, dict))
        return False
    if check_type == "has_program_routines":
        if isinstance(data, list):
            return any(item.get("programRoutines") for item in data if isinstance(item, dict))
        return False
    if check_type == "has_platforms":
        if isinstance(data, list):
            return any(item.get("platforms") for item in data if isinstance(item, dict))
        return False
    if check_type == "has_repo":
        if isinstance(data, list):
            return any(item.get("repo") for item in data if isinstance(item, dict))
        return False

    # ProblemTypes
    if check_type == "has_cwe":
        if isinstance(data, list):
            return any(
                any("cweId" in d for d in pt.get("descriptions", []))
                for pt in data if isinstance(pt, dict)
            )
        return False
    if check_type == "has_type":
        if isinstance(data, list):
            return any(pt.get("type") for pt in data if isinstance(pt, dict))
        return False
    if check_type == "has_pt_references":
        if isinstance(data, list):
            return any(pt.get("references") for pt in data if isinstance(pt, dict))
        return False

    # References
    if check_type == "has_advisory_ref":
        if isinstance(data, list):
            return any(ref.get("tags") and any("advisory" in str(tag).lower() for tag in ref["tags"])
                       for ref in data if isinstance(ref, dict))
        return False
    if check_type == "has_patch_ref":
        if isinstance(data, list):
            return any(ref.get("tags") and any("patch" in str(tag).lower() for tag in ref["tags"])
                       for ref in data if isinstance(ref, dict))
        return False
    if check_type == "has_exploit_ref":
        if isinstance(data, list):
            return any(ref.get("tags") and any("exploit" in str(tag).lower() for tag in ref["tags"])
                       for ref in data if isinstance(ref, dict))
        return False
    if check_type == "has_technical_ref":
        if isinstance(data, list):
            return any(ref.get("tags") and any("technical" in str(tag).lower() for tag in ref["tags"])
                       for ref in data if isinstance(ref, dict))
        return False
    if check_type == "has_vendor_ref":
        if isinstance(data, list):
            return any(ref.get("tags") and any("vendor" in str(tag).lower() for tag in ref["tags"])
                       for ref in data if isinstance(ref, dict))
        return False
    if check_type == "has_named_ref":
        if isinstance(data, list):
            return any(ref.get("name") for ref in data if isinstance(ref, dict))
        return False

    # Metrics
    if check_type == "has_cvss_v4":
        if isinstance(data, dict):
            return "cvssV4" in data
        return False
    if check_type == "has_cvss_v3_1":
        if isinstance(data, dict):
            return "cvssV3_1" in data
        return False
    if check_type == "has_cvss_v3_0":
        if isinstance(data, dict):
            return "cvssV3_0" in data
        return False
    if check_type == "has_cvss_v2":
        if isinstance(data, dict):
            return "cvssV2" in data
        return False
    if check_type == "has_other_metrics":
        if isinstance(data, dict):
            return any(k not in ("cvssV4", "cvssV3_1", "cvssV3_0", "cvssV2") for k in data.keys())
        return False
    if check_type == "has_scenarios":
        if isinstance(data, dict):
            return "scenarios" in data
        return False

    return False


def compute_field_utilization(cve_records, field_list):
    """
    Calculates the percentage of CNAs that have used each field.
    """
    schema_fields = _get_schema_fields()
    cna_field_usage = defaultdict(set)
    all_cnas = set()

    for cve in cve_records:
        cna_id = _get_nested_value(cve, ["cveMetadata", "assignerOrgId"])
        if not cna_id:
            continue
        all_cnas.add(cna_id)

        for field_name in field_list:
            if field_name not in schema_fields:
                continue
            
            field_info = schema_fields[field_name]
            path = field_info["path"]
            check_type = field_info.get("check")
            
            value = _get_nested_value(cve, path)
            
            is_present = False
            if check_type:
                is_present = _custom_check(value, check_type)
            elif value is not None and value != []:
                is_present = True
            
            if is_present:
                cna_field_usage[field_name].add(cna_id)

    total_cnas = len(all_cnas)
    utilization = []
    for field in field_list:
        unique_cnas = len(cna_field_usage[field])
        cna_percent = round(100 * unique_cnas / total_cnas, 1) if total_cnas else 0
        utilization.append({
            "field": field,
            "unique_cnas": unique_cnas,
            "cna_percent": cna_percent
        })
    # Sort by cna_percent descending, then field name ascending
    utilization.sort(key=lambda x: (-x['cna_percent'], x['field']))
    return utilization
