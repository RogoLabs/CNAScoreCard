#!/usr/bin/env python3
"""
Test script to validate CVSS and CWE detection logic
"""

def detect_cvss(cve_record):
    """Test CVSS detection logic"""
    has_cvss = False
    if 'metrics' in cve_record:
        # metrics is an array of metric objects
        for metric in cve_record['metrics']:
            # Each metric can have cvssV3_1, cvssV3_0, cvssV2_0, etc.
            if any(key.startswith('cvssV') for key in metric.keys()):
                # For modern CVSS (v3+), require both baseScore and vectorString
                for cvss_key in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
                    if cvss_key in metric:
                        cvss_data = metric[cvss_key]
                        vector_string = cvss_data.get('vectorString')
                        if (isinstance(cvss_data, dict) and 
                            cvss_data.get('baseScore') is not None and
                            vector_string and
                            isinstance(vector_string, str) and
                            len(vector_string) > 0):
                            has_cvss = True
                            break
                # For CVSS v2, just require baseScore (less strict)
                if not has_cvss and 'cvssV2' in metric:
                    cvss_data = metric['cvssV2']
                    if isinstance(cvss_data, dict) and cvss_data.get('baseScore') is not None:
                        has_cvss = True
                if has_cvss:
                    break
    return has_cvss

def detect_cwe(cve_record):
    """Test CWE detection logic"""
    has_cwe = False
    if 'problemTypes' in cve_record:
        # problemTypes is an array of problemType objects
        for problem_type in cve_record['problemTypes']:
            if 'descriptions' in problem_type:
                # descriptions is an array of description objects
                for description in problem_type['descriptions']:
                    # CWE references should be in 'cweId' field with proper format
                    cwe_id = description.get('cweId', '')
                    if (cwe_id and isinstance(cwe_id, str) and 
                        cwe_id.startswith('CWE-') and 
                        cwe_id[4:].isdigit()):
                        has_cwe = True
                        break
            if has_cwe:
                break
    return has_cwe

def test_cvss_detection():
    """Test CVSS score detection"""
    print("Testing CVSS detection...")
    
    # Test CVE with CVSS v3.1
    cve_with_cvss = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST1",
            "assignerShortName": "test-cna"
        },
        "containers": {
            "cna": {
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 7.5,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
                        }
                    }
                ]
            }
        }
    }
    
    # Test CVE without CVSS
    cve_without_cvss = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST2",
            "assignerShortName": "test-cna"
        },
        "containers": {
            "cna": {}
        }
    }
    
    result1 = detect_cvss(cve_with_cvss)
    result2 = detect_cvss(cve_without_cvss)
    
    assert result1 == True, "Should detect CVSS score"
    assert result2 == False, "Should not detect CVSS score"
    print("✓ CVSS detection tests passed")

def test_cwe_detection():
    """Test CWE ID detection"""
    print("Testing CWE detection...")
    
    # Test CVE with CWE ID
    cve_with_cwe = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST3",
            "assignerShortName": "test-cna"
        },
        "containers": {
            "cna": {
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
    
    # Test CVE with invalid CWE format
    cve_with_invalid_cwe = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST4",
            "assignerShortName": "test-cna"
        },
        "containers": {
            "cna": {
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "description": "CWE-79",
                                "cweId": "Other"
                            }
                        ]
                    }
                ]
            }
        }
    }
    
    # Test CVE without CWE
    cve_without_cwe = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST5",
            "assignerShortName": "test-cna"
        },
        "containers": {
            "cna": {
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "description": "Some vulnerability"
                            }
                        ]
                    }
                ]
            }
        }
    }
    
    result1 = detect_cwe(cve_with_cwe)
    result2 = detect_cwe(cve_with_invalid_cwe)
    result3 = detect_cwe(cve_without_cwe)
    
    assert result1 == True, "Should detect CWE ID"
    assert result2 == False, "Should not detect invalid CWE format"
    assert result3 == False, "Should not detect CWE"
    print("✓ CWE detection tests passed")

def test_combined_scenarios():
    """Test various combinations"""
    print("Testing combined scenarios...")
    
    # CVE with both CVSS and CWE
    cve_complete = {
        "cveMetadata": {
            "cveId": "CVE-2023-TEST6",
            "assignerShortName": "test-cna"
        },
        "containers": {
            "cna": {
                "metrics": [
                    {
                        "cvssV3_0": {
                            "baseScore": 9.8,
                            "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "cweId": "CWE-78"
                            }
                        ]
                    }
                ]
            }
        }
    }
    
    has_cvss = detect_cvss(cve_complete)
    has_cwe = detect_cwe(cve_complete)
    
    assert has_cvss == True, "Should detect CVSS"
    assert has_cwe == True, "Should detect CWE"
    print("✓ Combined scenario tests passed")

def main():
    """Run all tests"""
    print("Starting CVSS and CWE detection tests...\n")
    
    try:
        test_cvss_detection()
        test_cwe_detection()
        test_combined_scenarios()
        
        print("\n🎉 All tests passed! The CVSS and CWE detection logic is working correctly.")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    import sys
    success = main()
    sys.exit(0 if success else 1)