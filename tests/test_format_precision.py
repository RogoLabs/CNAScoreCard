#!/usr/bin/env python3
"""
Test script to validate the updated Data Format & Precision scoring logic
"""

import sys
import os
import json

# Add the parent directory to the path to import the scorer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from cnascorecard.eas_scorer import EnhancedAggregateScorer

def test_format_precision_all_pass():
    """Test CVE with all format requirements met - should get 5 points"""
    cve_data = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST1",
            "assignerShortName": "test-cna"
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
    
    assert result['scoreBreakdown']['dataFormatAndPrecision'] == 5, f"Expected 5 points, got {result['scoreBreakdown']['dataFormatAndPrecision']}"
    print("✓ All format requirements pass test passed")

def test_format_precision_missing_cvss_vector():
    """Test CVE missing CVSS vector string - should get 0 points"""
    cve_data = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST2",
            "assignerShortName": "test-cna"
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
                        "cpes": ["cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"]
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 9.8
                            # Missing vectorString
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
    
    assert result['scoreBreakdown']['dataFormatAndPrecision'] == 0, f"Expected 0 points, got {result['scoreBreakdown']['dataFormatAndPrecision']}"
    print("✓ Missing CVSS vector string test passed")

def test_format_precision_invalid_cwe():
    """Test CVE with invalid CWE format - should get 0 points"""
    cve_data = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST3",
            "assignerShortName": "test-cna"
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
                                "cweId": "Other"  # Invalid CWE format
                            }
                        ]
                    }
                ]
            }
        }
    }
    
    scorer = EnhancedAggregateScorer(cve_data)
    result = scorer.calculate_scores()
    
    assert result['scoreBreakdown']['dataFormatAndPrecision'] == 0, f"Expected 0 points, got {result['scoreBreakdown']['dataFormatAndPrecision']}"
    print("✓ Invalid CWE format test passed")

def test_format_precision_missing_cpe():
    """Test CVE missing CPE identifiers - should get 0 points"""
    cve_data = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST4",
            "assignerShortName": "test-cna"
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
                        "product": "HTTP Server"
                        # Missing CPE
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
    
    assert result['scoreBreakdown']['dataFormatAndPrecision'] == 0, f"Expected 0 points, got {result['scoreBreakdown']['dataFormatAndPrecision']}"
    print("✓ Missing CPE test passed")

def main():
    """Run all Data Format & Precision tests"""
    print("Starting Data Format & Precision tests...\n")
    
    try:
        test_format_precision_all_pass()
        test_format_precision_missing_cvss_vector()
        test_format_precision_invalid_cwe()
        test_format_precision_missing_cpe()
        
        print("\n🎉 All Data Format & Precision tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)