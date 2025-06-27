#!/usr/bin/env python3
"""
CVE Data Completeness Analyzer

This module evaluates the completeness of CVE records by comparing their fields
and arrays against the CVE schema structure. It calculates the percentage of
presence for each field in the CVE records to ensure alignment with the schema.
"""

import json
import os
import logging
from typing import Dict, Any, List, Tuple, Optional, Set
from collections import defaultdict
import statistics

logger = logging.getLogger(__name__)

class CVECompletenessAnalyzer:
    """Analyzes CVE records for completeness against the CVE schema."""
    
    def __init__(self):
        """Initialize the completeness analyzer."""
        self.schema_fields = self._get_schema_fields()
        self.field_stats = defaultdict(lambda: {"present": 0, "total": 0, "percentage": 0.0})
        
    def _get_schema_fields(self) -> Dict[str, Dict]:
        """Define the key CVE schema fields for completeness analysis.
        
        Note: The following 10 fields are automatically added by the CVE program
        and are excluded from completeness tracking:
        - dataType
        - dataVersion 
        - cveMetadata.cveId
        - cveMetadata.assignerOrgId
        - cveMetadata.state 
        - containers.cna.providerMetadata
        - cveMetadata.assignerShortName
        - cveMetadata.dateUpdated 
        - cveMetadata.datePublished 
        - cveMetadata.dateReserved
        """
        return {
            # CVE Metadata - Only track fields not automatically added
            "cveMetadata.serial": {"required": False, "path": ["cveMetadata", "serial"]},
            
            # CNA Container - Required fields (excluding providerMetadata which is auto-added)
            "containers.cna.descriptions": {"required": True, "path": ["containers", "cna", "descriptions"]},
            "containers.cna.affected": {"required": True, "path": ["containers", "cna", "affected"]},
            "containers.cna.references": {"required": True, "path": ["containers", "cna", "references"]},
            
            # CNA Container - Optional but important fields
            "containers.cna.title": {"required": False, "path": ["containers", "cna", "title"]},
            "containers.cna.dateAssigned": {"required": False, "path": ["containers", "cna", "dateAssigned"]},
            "containers.cna.datePublic": {"required": False, "path": ["containers", "cna", "datePublic"]},
            "containers.cna.problemTypes": {"required": False, "path": ["containers", "cna", "problemTypes"]},
            "containers.cna.metrics": {"required": False, "path": ["containers", "cna", "metrics"]},
            "containers.cna.impacts": {"required": False, "path": ["containers", "cna", "impacts"]},
            "containers.cna.configurations": {"required": False, "path": ["containers", "cna", "configurations"]},
            "containers.cna.workarounds": {"required": False, "path": ["containers", "cna", "workarounds"]},
            "containers.cna.solutions": {"required": False, "path": ["containers", "cna", "solutions"]},
            "containers.cna.exploits": {"required": False, "path": ["containers", "cna", "exploits"]},
            "containers.cna.timeline": {"required": False, "path": ["containers", "cna", "timeline"]},
            "containers.cna.credits": {"required": False, "path": ["containers", "cna", "credits"]},
            "containers.cna.source": {"required": False, "path": ["containers", "cna", "source"]},
            "containers.cna.tags": {"required": False, "path": ["containers", "cna", "tags"]},
            "containers.cna.taxonomyMappings": {"required": False, "path": ["containers", "cna", "taxonomyMappings"]},
            "containers.cna.cpeApplicability": {"required": False, "path": ["containers", "cna", "cpeApplicability"]},
            
            # ADP Container (if present)
            "containers.adp": {"required": False, "path": ["containers", "adp"]},
            
            # Detailed analysis for key arrays/objects
            
            # Descriptions analysis
            "descriptions.english": {"required": True, "path": ["containers", "cna", "descriptions"], "custom_check": "english_description"},
            "descriptions.multiple_languages": {"required": False, "path": ["containers", "cna", "descriptions"], "custom_check": "multiple_languages"},
            "descriptions.supporting_media": {"required": False, "path": ["containers", "cna", "descriptions"], "custom_check": "supporting_media"},
            
            # Affected products analysis
            "affected.vendor": {"required": True, "path": ["containers", "cna", "affected"], "custom_check": "has_vendor"},
            "affected.product": {"required": True, "path": ["containers", "cna", "affected"], "custom_check": "has_product"},
            "affected.versions": {"required": False, "path": ["containers", "cna", "affected"], "custom_check": "has_versions"},
            "affected.defaultStatus": {"required": False, "path": ["containers", "cna", "affected"], "custom_check": "has_default_status"},
            "affected.cpes": {"required": False, "path": ["containers", "cna", "affected"], "custom_check": "has_cpes"},
            "affected.modules": {"required": False, "path": ["containers", "cna", "affected"], "custom_check": "has_modules"},
            "affected.programFiles": {"required": False, "path": ["containers", "cna", "affected"], "custom_check": "has_program_files"},
            "affected.programRoutines": {"required": False, "path": ["containers", "cna", "affected"], "custom_check": "has_program_routines"},
            "affected.platforms": {"required": False, "path": ["containers", "cna", "affected"], "custom_check": "has_platforms"},
            "affected.repo": {"required": False, "path": ["containers", "cna", "affected"], "custom_check": "has_repo"},
            
            # Problem Types analysis
            "problemTypes.cwe": {"required": False, "path": ["containers", "cna", "problemTypes"], "custom_check": "has_cwe"},
            "problemTypes.type": {"required": False, "path": ["containers", "cna", "problemTypes"], "custom_check": "has_type"},
            "problemTypes.references": {"required": False, "path": ["containers", "cna", "problemTypes"], "custom_check": "has_pt_references"},
            
            # References analysis
            "references.advisory": {"required": False, "path": ["containers", "cna", "references"], "custom_check": "has_advisory_ref"},
            "references.patch": {"required": False, "path": ["containers", "cna", "references"], "custom_check": "has_patch_ref"},
            "references.exploit": {"required": False, "path": ["containers", "cna", "references"], "custom_check": "has_exploit_ref"},
            "references.technical": {"required": False, "path": ["containers", "cna", "references"], "custom_check": "has_technical_ref"},
            "references.vendor": {"required": False, "path": ["containers", "cna", "references"], "custom_check": "has_vendor_ref"},
            "references.named": {"required": False, "path": ["containers", "cna", "references"], "custom_check": "has_named_ref"},
            
            # Metrics analysis
            "metrics.cvssV4": {"required": False, "path": ["containers", "cna", "metrics"], "custom_check": "has_cvss_v4"},
            "metrics.cvssV3_1": {"required": False, "path": ["containers", "cna", "metrics"], "custom_check": "has_cvss_v3_1"},
            "metrics.cvssV3_0": {"required": False, "path": ["containers", "cna", "metrics"], "custom_check": "has_cvss_v3_0"},
            "metrics.cvssV2": {"required": False, "path": ["containers", "cna", "metrics"], "custom_check": "has_cvss_v2"},
            "metrics.other": {"required": False, "path": ["containers", "cna", "metrics"], "custom_check": "has_other_metrics"},
            "metrics.scenarios": {"required": False, "path": ["containers", "cna", "metrics"], "custom_check": "has_scenarios"},
        }
    
    def _get_nested_value(self, data: Dict[str, Any], path: List[str]) -> Any:
        """Get a nested value from a dictionary using a path list."""
        current = data
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            elif isinstance(current, list) and key.isdigit():
                idx = int(key)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return None
            else:
                return None
        return current
    
    def _check_custom_field(self, cve_data: Dict[str, Any], check_type: str, path: List[str]) -> bool:
        """Perform custom field checks for complex schema validations."""
        data = self._get_nested_value(cve_data, path)
        if not data:
            return False
            
        if check_type == "english_description":
            if isinstance(data, list):
                return any(desc.get("lang", "").lower().startswith("en") for desc in data)
            return False
            
        elif check_type == "multiple_languages":
            if isinstance(data, list):
                languages = set(desc.get("lang", "") for desc in data)
                return len(languages) > 1
            return False
            
        elif check_type == "supporting_media":
            if isinstance(data, list):
                return any("supportingMedia" in desc for desc in data)
            return False
            
        elif check_type == "has_vendor":
            if isinstance(data, list):
                return any(item.get("vendor") for item in data)
            return False
            
        elif check_type == "has_product":
            if isinstance(data, list):
                return any(item.get("product") for item in data)
            return False
            
        elif check_type == "has_versions":
            if isinstance(data, list):
                return any(item.get("versions") and len(item["versions"]) > 0 for item in data)
            return False
            
        elif check_type == "has_default_status":
            if isinstance(data, list):
                return any(item.get("defaultStatus") for item in data)
            return False
            
        elif check_type == "has_cpes":
            if isinstance(data, list):
                return any(item.get("cpes") and len(item["cpes"]) > 0 for item in data)
            return False
            
        elif check_type == "has_modules":
            if isinstance(data, list):
                return any(item.get("modules") and len(item["modules"]) > 0 for item in data)
            return False
            
        elif check_type == "has_program_files":
            if isinstance(data, list):
                return any(item.get("programFiles") and len(item["programFiles"]) > 0 for item in data)
            return False
            
        elif check_type == "has_program_routines":
            if isinstance(data, list):
                return any(item.get("programRoutines") and len(item["programRoutines"]) > 0 for item in data)
            return False
            
        elif check_type == "has_platforms":
            if isinstance(data, list):
                return any(item.get("platforms") and len(item["platforms"]) > 0 for item in data)
            return False
            
        elif check_type == "has_repo":
            if isinstance(data, list):
                return any(item.get("repo") for item in data)
            return False
            
        elif check_type == "has_cwe":
            if isinstance(data, list):
                for pt in data:
                    if isinstance(pt, dict) and pt.get("descriptions"):
                        for desc in pt["descriptions"]:
                            if desc.get("cweId"):
                                return True
            return False
            
        elif check_type == "has_type":
            if isinstance(data, list):
                for pt in data:
                    if isinstance(pt, dict) and pt.get("descriptions"):
                        for desc in pt["descriptions"]:
                            if desc.get("type"):
                                return True
            return False
            
        elif check_type == "has_pt_references":
            if isinstance(data, list):
                for pt in data:
                    if isinstance(pt, dict) and pt.get("descriptions"):
                        for desc in pt["descriptions"]:
                            if desc.get("references"):
                                return True
            return False
            
        elif check_type == "has_advisory_ref":
            if isinstance(data, list):
                return any(ref.get("tags") and any("advisory" in str(tag).lower() for tag in ref["tags"]) 
                          for ref in data if isinstance(ref, dict))
            return False
            
        elif check_type == "has_patch_ref":
            if isinstance(data, list):
                return any(ref.get("tags") and any("patch" in str(tag).lower() for tag in ref["tags"]) 
                          for ref in data if isinstance(ref, dict))
            return False
            
        elif check_type == "has_exploit_ref":
            if isinstance(data, list):
                return any(ref.get("tags") and any("exploit" in str(tag).lower() for tag in ref["tags"]) 
                          for ref in data if isinstance(ref, dict))
            return False
            
        elif check_type == "has_technical_ref":
            if isinstance(data, list):
                return any(ref.get("tags") and any("technical" in str(tag).lower() for tag in ref["tags"]) 
                          for ref in data if isinstance(ref, dict))
            return False
            
        elif check_type == "has_vendor_ref":
            if isinstance(data, list):
                return any(ref.get("tags") and any("vendor" in str(tag).lower() for tag in ref["tags"]) 
                          for ref in data if isinstance(ref, dict))
            return False
            
        elif check_type == "has_named_ref":
            if isinstance(data, list):
                return any(ref.get("name") for ref in data if isinstance(ref, dict))
            return False
            
        elif check_type == "has_cvss_v4":
            if isinstance(data, list):
                return any(metric.get("cvssV4_0") for metric in data if isinstance(metric, dict))
            return False
            
        elif check_type == "has_cvss_v3_1":
            if isinstance(data, list):
                return any(metric.get("cvssV3_1") for metric in data if isinstance(metric, dict))
            return False
            
        elif check_type == "has_cvss_v3_0":
            if isinstance(data, list):
                return any(metric.get("cvssV3_0") for metric in data if isinstance(metric, dict))
            return False
            
        elif check_type == "has_cvss_v2":
            if isinstance(data, list):
                return any(metric.get("cvssV2_0") for metric in data if isinstance(metric, dict))
            return False
            
        elif check_type == "has_other_metrics":
            if isinstance(data, list):
                return any(metric.get("other") for metric in data if isinstance(metric, dict))
            return False
            
        elif check_type == "has_scenarios":
            if isinstance(data, list):
                return any(metric.get("scenarios") for metric in data if isinstance(metric, dict))
            return False
            
        return False
    
    def analyze_cve(self, cve_data: Dict[str, Any]) -> Dict[str, bool]:
        """Analyze a single CVE record for completeness."""
        results = {}
        
        for field_name, field_config in self.schema_fields.items():
            if "custom_check" in field_config:
                # Custom field check
                results[field_name] = self._check_custom_field(
                    cve_data, field_config["custom_check"], field_config["path"]
                )
            else:
                # Direct path check
                value = self._get_nested_value(cve_data, field_config["path"])
                results[field_name] = value is not None and value != ""
                
        return results
    
    def analyze_batch(self, cve_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze a batch of CVE records and calculate completeness statistics."""
        total_records = len(cve_records)
        
        # Reset field stats
        self.field_stats = defaultdict(lambda: {"present": 0, "total": 0, "percentage": 0.0})
        
        # Track CNA-specific stats
        cna_stats = defaultdict(lambda: defaultdict(lambda: {"present": 0, "total": 0, "percentage": 0.0}))
        
        # Track CVEs with missing required fields
        cves_missing_required = []
        
        for cve_data in cve_records:
            cve_results = self.analyze_cve(cve_data)
            
            # Get CVE information
            cve_id = self._get_nested_value(cve_data, ["cveMetadata", "cveId"]) or "Unknown"
            cna_name = self._get_nested_value(cve_data, ["cveMetadata", "assignerShortName"]) or \
                      self._get_nested_value(cve_data, ["containers", "cna", "providerMetadata", "shortName"]) or \
                      "Unknown"
            date_published = self._get_nested_value(cve_data, ["cveMetadata", "datePublished"])
            
            # Check for missing required fields
            missing_required = []
            for field_name, field_config in self.schema_fields.items():
                if field_config["required"] and not cve_results.get(field_name, False):
                    missing_required.append(field_name)
            
            # If CVE has missing required fields, track it
            if missing_required:
                cves_missing_required.append({
                    "cveId": cve_id,
                    "assigningCna": cna_name,
                    "datePublished": date_published,
                    "missingRequiredFields": missing_required
                })
            
            # Update global statistics
            for field_name, is_present in cve_results.items():
                self.field_stats[field_name]["total"] += 1
                if is_present:
                    self.field_stats[field_name]["present"] += 1
                    
                # Update per-CNA statistics
                cna_stats[cna_name][field_name]["total"] += 1
                if is_present:
                    cna_stats[cna_name][field_name]["present"] += 1
        
        # Calculate percentages
        for field_name in self.field_stats:
            total = self.field_stats[field_name]["total"]
            if total > 0:
                self.field_stats[field_name]["percentage"] = \
                    (self.field_stats[field_name]["present"] / total) * 100
                    
        # Calculate per-CNA percentages
        for cna_name in cna_stats:
            for field_name in cna_stats[cna_name]:
                total = cna_stats[cna_name][field_name]["total"]
                if total > 0:
                    cna_stats[cna_name][field_name]["percentage"] = \
                        (cna_stats[cna_name][field_name]["present"] / total) * 100
        
        return {
            "total_records": total_records,
            "global_stats": dict(self.field_stats),
            "cna_stats": dict(cna_stats),
            "completeness_summary": self._generate_completeness_summary(),
            "cves_missing_required_fields": cves_missing_required
        }
    
    def _generate_completeness_summary(self) -> Dict[str, Any]:
        """Generate a summary of completeness statistics."""
        required_fields = []
        optional_fields = []
        
        for field_name, field_config in self.schema_fields.items():
            field_stats = self.field_stats[field_name]
            field_info = {
                "field": field_name,
                "required": field_config["required"],
                "percentage": field_stats["percentage"],
                "present": field_stats["present"],
                "total": field_stats["total"]
            }
            
            if field_config["required"]:
                required_fields.append(field_info)
            else:
                optional_fields.append(field_info)
        
        # Sort by percentage (lowest first for required, highest first for optional)
        required_fields.sort(key=lambda x: x["percentage"])
        optional_fields.sort(key=lambda x: x["percentage"], reverse=True)
        
        # Calculate overall completeness scores
        required_percentages = [f["percentage"] for f in required_fields if f["total"] > 0]
        optional_percentages = [f["percentage"] for f in optional_fields if f["total"] > 0]
        
        overall_required = statistics.mean(required_percentages) if required_percentages else 0
        overall_optional = statistics.mean(optional_percentages) if optional_percentages else 0
        overall_completeness = (overall_required * 0.7) + (overall_optional * 0.3)  # Weight required fields more
        
        return {
            "overall_completeness": overall_completeness,
            "required_fields_completeness": overall_required,
            "optional_fields_completeness": overall_optional,
            "required_fields": required_fields,
            "optional_fields": optional_fields,
            "top_missing_required": [f for f in required_fields if f["percentage"] < 95][:10],
            "top_present_optional": optional_fields[:10]
        }
    
    def get_cna_completeness_score(self, cna_name: str, cna_stats: Dict) -> float:
        """Calculate a completeness score for a specific CNA."""
        if cna_name not in cna_stats:
            return 0.0
            
        cna_data = cna_stats[cna_name]
        required_scores = []
        optional_scores = []
        
        for field_name, field_config in self.schema_fields.items():
            if field_name in cna_data:
                percentage = cna_data[field_name]["percentage"]
                if field_config["required"]:
                    required_scores.append(percentage)
                else:
                    optional_scores.append(percentage)
        
        required_avg = statistics.mean(required_scores) if required_scores else 0
        optional_avg = statistics.mean(optional_scores) if optional_scores else 0
        
        # Weight required fields more heavily
        return (required_avg * 0.7) + (optional_avg * 0.3)
