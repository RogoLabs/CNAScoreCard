#!/usr/bin/env python3
"""
Test script to validate the updated scoring logic for different components.
"""

import sys
import os
import json

# Add the parent directory to the path to import the scorer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from cnascorecard.eas_scorer import EnhancedAggregateScorer

def test_scoring_all_components_pass():
    """Test CVE with all format requirements met - should get max points in related components"""
    cve_data = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST1",
            "assignerShortName": "test-cna",
            "datePublished": "2023-01-01T00:00:00Z"
        },
        "containers": {
            "cna": {
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow vulnerability in Apache HTTP Server"
                    }
                ],
                "affected": [
                    {
                        "vendor": "Apache",
                        "product": "HTTP Server",
                        "versions": [{"version": "2.4.52", "status": "affected"}],
                        "cpes": ["cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"]
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
                ]
            }
        }
    }
    
    scorer = EnhancedAggregateScorer(cve_data)
    result = scorer.calculate_scores()
    
    assert result['scoreBreakdown']['foundationalCompleteness'] == 5, f"Expected 5 for foundational, got {result['scoreBreakdown']['foundationalCompleteness']}"
    assert result['scoreBreakdown']['rootCauseAnalysis'] == 3, f"Expected 3 for root cause, got {result['scoreBreakdown']['rootCauseAnalysis']}"
    assert result['scoreBreakdown']['softwareIdentification'] == 5, f"Expected 5 for software id, got {result['scoreBreakdown']['softwareIdentification']}"
    assert result['scoreBreakdown']['severityAndImpactContext'] == 3, f"Expected 3 for severity, got {result['scoreBreakdown']['severityAndImpactContext']}"
    print("✓ All components pass test passed")

def test_severity_context_missing_cvss_vector():
    """Test CVE missing CVSS vector string - should get lower severity score"""
    cve_data = {
        "cveMetadata": {"cveId": "CVE-2023-TEST2"},
        "containers": {
            "cna": {
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 9.8
                        }
                    }
                ]
            }
        }
    }
    
    scorer = EnhancedAggregateScorer(cve_data)
    result = scorer.calculate_scores()
    
    assert result['scoreBreakdown']['severityAndImpactContext'] == 1, f"Expected 1 for severity, got {result['scoreBreakdown']['severityAndImpactContext']}"
    print("✓ Missing CVSS vector string test passed")

def test_root_cause_analysis_invalid_cwe():
    """Test CVE with invalid CWE format - should get lower root cause score"""
    cve_data = {
        "cveMetadata": {"cveId": "CVE-2023-TEST3"},
        "containers": {
            "cna": {
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "description": "Buffer Overflow",
                                "cweId": "Other"
                            }
                        ]
                    }
                ]
            }
        }
    }
    
    scorer = EnhancedAggregateScorer(cve_data)
    result = scorer.calculate_scores()
    
    assert result['scoreBreakdown']['rootCauseAnalysis'] == 2, f"Expected 2 for root cause, got {result['scoreBreakdown']['rootCauseAnalysis']}"
    print("✓ Invalid CWE format test passed")

def test_software_identification_missing_cpe():
    """Test CVE missing CPE identifiers - should get lower software id score"""
    cve_data = {
        "cveMetadata": {"cveId": "CVE-2023-TEST4"},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "Apache",
                        "product": "HTTP Server"
                    }
                ]
            }
        }
    }
    
    scorer = EnhancedAggregateScorer(cve_data)
    result = scorer.calculate_scores()
    
    assert result['scoreBreakdown']['softwareIdentification'] == 2, f"Expected 2 for software id, got {result['scoreBreakdown']['softwareIdentification']}"
    print("✓ Missing CPE test passed")

def main():
    """Run all scoring component tests"""
    print("Starting scoring component tests...\n")
    
    try:
        test_scoring_all_components_pass()
        test_severity_context_missing_cvss_vector()
        test_root_cause_analysis_invalid_cwe()
        test_software_identification_missing_cpe()
        
        print("\n🎉 All scoring component tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)