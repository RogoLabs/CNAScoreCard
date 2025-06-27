#!/usr/bin/env python3
"""
Main script for running CVE completeness analysis
"""

import json
import os
import sys
import logging
from datetime import datetime
from typing import Dict, Any, List

# Add the parent directory to Python path to import cnascorecard modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cnacompletness.completeness_analyzer import CVECompletenessAnalyzer
from cnascorecard import data_ingestor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_completeness_reports():
    """Generate comprehensive completeness analysis reports."""
    print("Starting CVE completeness analysis...")
    
    # Initialize the analyzer
    analyzer = CVECompletenessAnalyzer()
    
    # Get CVE records
    print("Fetching CVE records...")
    recent_cves = data_ingestor.get_cve_records()
    print(f"Found {len(recent_cves)} CVE records to analyze.")
    
    if not recent_cves:
        print("No CVE records found. Exiting.")
        return
    
    # Analyze completeness
    print("Analyzing completeness...")
    analysis_results = analyzer.analyze_batch(recent_cves)
    
    # Generate timestamp for output files
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory
    output_dir = os.path.join(os.path.dirname(__file__), "output")
    os.makedirs(output_dir, exist_ok=True)
    
    # Save detailed analysis results
    detailed_output_file = os.path.join(output_dir, f"completeness_analysis_{timestamp}.json")
    with open(detailed_output_file, 'w') as f:
        json.dump(analysis_results, f, indent=2)
    print(f"Detailed analysis saved to: {detailed_output_file}")
    
    # Generate CNA summary data for web interface
    cna_completeness_data = []
    
    for cna_name, cna_stats in analysis_results["cna_stats"].items():
        if cna_name != "Unknown" and cna_stats:
            completeness_score = analyzer.get_cna_completeness_score(cna_name, {cna_name: cna_stats})
            
            # Count total CVEs for this CNA
            total_cves = max([field_data["total"] for field_data in cna_stats.values()]) if cna_stats else 0
            
            # Calculate key metrics
            required_fields_avg = 0
            optional_fields_avg = 0
            required_count = 0
            optional_count = 0
            
            for field_name, field_stats in cna_stats.items():
                field_config = analyzer.schema_fields.get(field_name, {})
                if field_config.get("required", False):
                    required_fields_avg += field_stats["percentage"]
                    required_count += 1
                else:
                    optional_fields_avg += field_stats["percentage"]
                    optional_count += 1
            
            if required_count > 0:
                required_fields_avg = required_fields_avg / required_count
            if optional_count > 0:
                optional_fields_avg = optional_fields_avg / optional_count
            
            cna_data = {
                "cna": cna_name,
                "total_cves": total_cves,
                "completeness_score": round(completeness_score, 2),
                "required_fields_completeness": round(required_fields_avg, 2),
                "optional_fields_completeness": round(optional_fields_avg, 2),
                "key_metrics": {
                    "has_descriptions": cna_stats.get("containers.cna.descriptions", {}).get("percentage", 0),
                    "has_affected": cna_stats.get("containers.cna.affected", {}).get("percentage", 0),
                    "has_references": cna_stats.get("containers.cna.references", {}).get("percentage", 0),
                    "has_problem_types": cna_stats.get("containers.cna.problemTypes", {}).get("percentage", 0),
                    "has_metrics": cna_stats.get("containers.cna.metrics", {}).get("percentage", 0),
                    "has_solutions": cna_stats.get("containers.cna.solutions", {}).get("percentage", 0)
                }
            }
            cna_completeness_data.append(cna_data)
    
    # Sort by completeness score
    cna_completeness_data.sort(key=lambda x: x["completeness_score"], reverse=True)
    
    # Add percentile rankings
    total_cnas = len(cna_completeness_data)
    for i, cna_data in enumerate(cna_completeness_data):
        percentile = ((total_cnas - i) / total_cnas) * 100
        cna_data["percentile"] = round(percentile, 1)
    
    # Save CNA completeness data for web interface
    web_output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "web", "completeness")
    os.makedirs(web_output_dir, exist_ok=True)
    
    cna_completeness_file = os.path.join(web_output_dir, "cna_completeness.json")
    with open(cna_completeness_file, 'w') as f:
        json.dump(cna_completeness_data, f, indent=2)
    print(f"CNA completeness data saved to: {cna_completeness_file}")
    
    # Generate summary statistics for web interface
    summary_stats = {
        "generated_at": datetime.now().isoformat(),
        "total_cves_analyzed": analysis_results["total_records"],
        "total_cnas": len(cna_completeness_data),
        "global_completeness": analysis_results["completeness_summary"],
        "field_definitions": {
            field_name: {
                "required": config["required"],
                "description": _get_field_description(field_name)
            }
            for field_name, config in analyzer.schema_fields.items()
        }
    }
    
    summary_file = os.path.join(web_output_dir, "completeness_summary.json")
    with open(summary_file, 'w') as f:
        json.dump(summary_stats, f, indent=2)
    print(f"Summary statistics saved to: {summary_file}")
    
    # Print summary to console
    print("\n" + "="*60)
    print("CVE COMPLETENESS ANALYSIS SUMMARY")
    print("="*60)
    print(f"Total CVEs analyzed: {analysis_results['total_records']}")
    print(f"Total CNAs: {len(cna_completeness_data)}")
    print(f"Overall completeness: {analysis_results['completeness_summary']['overall_completeness']:.1f}%")
    print(f"Required fields completeness: {analysis_results['completeness_summary']['required_fields_completeness']:.1f}%")
    print(f"Optional fields completeness: {analysis_results['completeness_summary']['optional_fields_completeness']:.1f}%")
    
    print("\nTop 10 CNAs by completeness:")
    for i, cna in enumerate(cna_completeness_data[:10], 1):
        print(f"{i:2d}. {cna['cna']}: {cna['completeness_score']:.1f}% (CVEs: {cna['total_cves']})")
    
    print("\nTop missing required fields:")
    for field in analysis_results['completeness_summary']['top_missing_required'][:5]:
        print(f"  - {field['field']}: {field['percentage']:.1f}% present")
    
    print("\nAnalysis complete!")

def _get_field_description(field_name: str) -> str:
    """Get a human-readable description for a field."""
    descriptions = {
        "dataType": "Indicates the type of information (CVE_RECORD)",
        "dataVersion": "Version of the CVE schema used",
        "cveMetadata.cveId": "The CVE identifier",
        "cveMetadata.assignerOrgId": "UUID of the assigning organization",
        "cveMetadata.assignerShortName": "Short name of the assigning organization",
        "cveMetadata.state": "State of the CVE (PUBLISHED/REJECTED)",
        "cveMetadata.dateUpdated": "Date the record was last updated",
        "cveMetadata.datePublished": "Date the CVE was published",
        "cveMetadata.dateReserved": "Date the CVE ID was reserved",
        "cveMetadata.serial": "Serial number for record versioning",
        "containers.cna.providerMetadata": "Information about the CNA",
        "containers.cna.descriptions": "Vulnerability descriptions",
        "containers.cna.affected": "Affected products and versions",
        "containers.cna.references": "Reference URLs and documentation",
        "containers.cna.title": "Brief title or headline",
        "containers.cna.dateAssigned": "Date the CVE ID was assigned",
        "containers.cna.datePublic": "Date the vulnerability was disclosed publicly",
        "containers.cna.problemTypes": "Problem type information (CWE, etc.)",
        "containers.cna.metrics": "Impact metrics (CVSS scores)",
        "containers.cna.impacts": "Impact descriptions",
        "containers.cna.configurations": "Required configurations for exploitation",
        "containers.cna.workarounds": "Workarounds and mitigations",
        "containers.cna.solutions": "Solutions and remediations",
        "containers.cna.exploits": "Information about known exploits",
        "containers.cna.timeline": "Timeline of significant events",
        "containers.cna.credits": "Credits and acknowledgments",
        "containers.cna.source": "Source information",
        "containers.cna.tags": "CNA-provided tags",
        "containers.cna.taxonomyMappings": "Mappings to security taxonomies",
        "containers.cna.cpeApplicability": "CPE applicability information",
        "containers.adp": "Additional data from Authorized Data Publishers",
        "descriptions.english": "At least one English description",
        "descriptions.multiple_languages": "Multiple language descriptions",
        "descriptions.supporting_media": "Supporting media (diagrams, etc.)",
        "affected.vendor": "Vendor information in affected products",
        "affected.product": "Product information in affected products",
        "affected.versions": "Version information",
        "affected.defaultStatus": "Default vulnerability status",
        "affected.cpes": "Common Platform Enumeration identifiers",
        "affected.modules": "Affected modules or components",
        "affected.programFiles": "Affected source code files",
        "affected.programRoutines": "Affected functions or methods",
        "affected.platforms": "Affected platforms",
        "affected.repo": "Source code repository URL",
        "problemTypes.cwe": "Common Weakness Enumeration identifiers",
        "problemTypes.type": "Problem type classification",
        "problemTypes.references": "Problem type references",
        "references.advisory": "Advisory references",
        "references.patch": "Patch references",
        "references.exploit": "Exploit references",
        "references.technical": "Technical references",
        "references.vendor": "Vendor references",
        "references.named": "Named references",
        "metrics.cvssV4": "CVSS v4.0 metrics",
        "metrics.cvssV3_1": "CVSS v3.1 metrics",
        "metrics.cvssV3_0": "CVSS v3.0 metrics",
        "metrics.cvssV2": "CVSS v2.0 metrics",
        "metrics.other": "Other metric formats",
        "metrics.scenarios": "Metric scenarios"
    }
    return descriptions.get(field_name, f"Schema field: {field_name}")

if __name__ == "__main__":
    generate_completeness_reports()
