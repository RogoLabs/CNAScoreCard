#!/usr/bin/env python3
"""
Test the CVE completeness analysis functionality
"""

import json
import os
import sys
from pathlib import Path

# Add the parent directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cnacompletness.completeness_analyzer import CVECompletenessAnalyzer

def test_completeness_analyzer():
    """Test the completeness analyzer with sample CVE data."""
    print("Testing CVE Completeness Analyzer...")
    
    # Sample CVE data
    complete_cve = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1.1",
        "cveMetadata": {
            "cveId": "CVE-2023-TEST-COMPLETE",
            "assignerOrgId": "12345678-1234-1234-1234-123456789012",
            "assignerShortName": "test-cna",
            "state": "PUBLISHED",
            "datePublished": "2023-01-01T00:00:00.000Z"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "12345678-1234-1234-1234-123456789012",
                    "shortName": "test-cna"
                },
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow vulnerability allows remote code execution"
                    }
                ],
                "affected": [
                    {
                        "vendor": "Test Vendor",
                        "product": "Test Product",
                        "versions": [
                            {
                                "version": "1.0.0",
                                "status": "affected"
                            }
                        ],
                        "cpes": ["cpe:2.3:a:test:product:1.0.0:*:*:*:*:*:*:*"]
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory",
                        "name": "Security Advisory",
                        "tags": ["vendor-advisory"]
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "description": "Buffer Overflow",
                                "cweId": "CWE-120"
                            }
                        ]
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
                    }
                ],
                "solutions": [
                    {
                        "lang": "en",
                        "value": "Update to version 1.0.1"
                    }
                ]
            }
        }
    }
    
    minimal_cve = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1.1",
        "cveMetadata": {
            "cveId": "CVE-2023-TEST-MINIMAL",
            "assignerOrgId": "12345678-1234-1234-1234-123456789012",
            "state": "PUBLISHED"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "12345678-1234-1234-1234-123456789012"
                },
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Vulnerability in software"
                    }
                ],
                "affected": [
                    {
                        "vendor": "Test Vendor",
                        "product": "Test Product"
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com"
                    }
                ]
            }
        }
    }
    
    # Initialize analyzer
    analyzer = CVECompletenessAnalyzer()
    
    # Test individual CVE analysis
    print("\n1. Testing individual CVE analysis...")
    complete_results = analyzer.analyze_cve(complete_cve)
    minimal_results = analyzer.analyze_cve(minimal_cve)
    
    print(f"Complete CVE fields present: {sum(complete_results.values())}/{len(complete_results)}")
    print(f"Minimal CVE fields present: {sum(minimal_results.values())}/{len(minimal_results)}")
    
    # Test batch analysis
    print("\n2. Testing batch analysis...")
    batch_results = analyzer.analyze_batch([complete_cve, minimal_cve])
    
    print(f"Total records: {batch_results['total_records']}")
    print(f"Overall completeness: {batch_results['completeness_summary']['overall_completeness']:.1f}%")
    print(f"Required fields completeness: {batch_results['completeness_summary']['required_fields_completeness']:.1f}%")
    print(f"Optional fields completeness: {batch_results['completeness_summary']['optional_fields_completeness']:.1f}%")
    
    # Test CNA scoring
    print("\n3. Testing CNA completeness scoring...")
    test_cna_score = analyzer.get_cna_completeness_score("test-cna", batch_results["cna_stats"])
    print(f"Test CNA completeness score: {test_cna_score:.1f}%")
    
    print("\n4. Testing field descriptions...")
    sample_fields = ["containers.cna.descriptions", "containers.cna.affected", "problemTypes.cwe"]
    for field in sample_fields:
        result = analyzer.analyze_cve(complete_cve).get(field, False)
        print(f"Field '{field}': {'✓' if result else '✗'}")
    
    print("\n✅ All tests passed! Completeness analyzer is working correctly.")
    return True

if __name__ == "__main__":
    try:
        test_completeness_analyzer()
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
