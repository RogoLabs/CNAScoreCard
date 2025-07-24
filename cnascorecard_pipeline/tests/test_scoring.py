"""
Unit tests for scoring module.

This module tests the CVE scoring logic to ensure correct calculation
of category scores based on the CNA Scorecard methodology.
"""
import pytest
from unittest.mock import patch, MagicMock
from typing import Dict, Any

# Import the module under test
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scoring import (
    score_cve_record,
    score_multiple_cves,
    _calculate_foundational_completeness,
    _calculate_root_cause_analysis,
    _calculate_severity_context,
    _calculate_software_identification,
    _calculate_actionable_intelligence,
    _find_valid_cwe,
    _is_valid_cwe_id,
    _has_cvss_metrics,
    _has_valid_cvss_vector,
    _has_cpe_identifiers,
    _has_patch_references
)


class TestScoringFixtures:
    """Test fixtures for CVE scoring tests."""
    
    @pytest.fixture
    def sample_cve_complete(self) -> Dict[str, Any]:
        """Complete CVE record with all scoring fields present."""
        return {
            "cveId": "CVE-2024-12345",
            "cveMetadata": {
                "cveId": "CVE-2024-12345",
                "datePublished": "2024-01-15T10:00:00.000Z",
                "state": "PUBLISHED"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "shortName": "TestCNA"
                    },
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "A vulnerability in the test application allows remote code execution."
                        }
                    ],
                    "affected": [
                        {
                            "vendor": "TestVendor",
                            "product": "TestProduct",
                            "versions": [
                                {
                                    "version": "1.0.0",
                                    "status": "affected"
                                }
                            ],
                            "cpes": ["cpe:2.3:a:testvendor:testproduct:1.0.0:*:*:*:*:*:*:*"]
                        }
                    ],
                    "references": [
                        {
                            "url": "https://example.com/patch",
                            "tags": ["patch"]
                        },
                        {
                            "url": "https://example.com/advisory",
                            "tags": ["vendor-advisory"]
                        }
                    ],
                    "problemTypes": [
                        {
                            "descriptions": [
                                {
                                    "cweId": "CWE-78",
                                    "description": "OS Command Injection"
                                }
                            ]
                        }
                    ],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL"
                            }
                        }
                    ]
                }
            }
        }
    
    @pytest.fixture
    def sample_cve_minimal(self) -> Dict[str, Any]:
        """Minimal CVE record with no scoring fields."""
        return {
            "cveId": "CVE-2024-67890",
            "cveMetadata": {
                "cveId": "CVE-2024-67890",
                "datePublished": "2024-01-15T10:00:00.000Z",
                "state": "PUBLISHED"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "shortName": "MinimalCNA"
                    }
                }
            }
        }
    
    @pytest.fixture
    def sample_cve_partial(self) -> Dict[str, Any]:
        """Partially complete CVE record."""
        return {
            "cveId": "CVE-2024-11111",
            "cveMetadata": {
                "cveId": "CVE-2024-11111",
                "datePublished": "2024-01-15T10:00:00.000Z",
                "state": "PUBLISHED"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "shortName": "PartialCNA"
                    },
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "A vulnerability exists."
                        }
                    ],
                    "affected": [
                        {
                            "vendor": "TestVendor",
                            "product": "TestProduct"
                        }
                    ],
                    "references": [
                        {
                            "url": "https://example.com/info",
                            "tags": ["vendor-advisory"]
                        }
                    ]
                }
            }
        }


class TestScoreCveRecord(TestScoringFixtures):
    """Test the main score_cve_record function."""
    
    def test_score_complete_cve(self, sample_cve_complete):
        """Test scoring a complete CVE record."""
        result = score_cve_record(sample_cve_complete)
        
        assert result["cveId"] == "CVE-2024-12345"
        assert result["assigningCna"] == "TestCNA"
        assert result["datePublished"] == "2024-01-15"
        assert result["totalScore"] == 100  # All categories should score full points
        
        breakdown = result["scoreBreakdown"]
        assert breakdown["foundationalCompleteness"] == 50
        assert breakdown["rootCauseAnalysis"] == 15
        assert breakdown["severityAndImpactContext"] == 15
        assert breakdown["softwareIdentification"] == 10
        assert breakdown["patchinfo"] == 10
    
    def test_score_minimal_cve(self, sample_cve_minimal):
        """Test scoring a minimal CVE record."""
        result = score_cve_record(sample_cve_minimal)
        
        assert result["cveId"] == "CVE-2024-67890"
        assert result["assigningCna"] == "MinimalCNA"
        assert result["totalScore"] == 0  # No scoring fields present
        
        breakdown = result["scoreBreakdown"]
        assert all(score == 0 for score in breakdown.values())
    
    def test_score_partial_cve(self, sample_cve_partial):
        """Test scoring a partially complete CVE record."""
        result = score_cve_record(sample_cve_partial)
        
        assert result["cveId"] == "CVE-2024-11111"
        assert result["assigningCna"] == "PartialCNA"
        assert result["totalScore"] == 50  # Only foundational completeness
        
        breakdown = result["scoreBreakdown"]
        assert breakdown["foundationalCompleteness"] == 50
        assert breakdown["rootCauseAnalysis"] == 0
        assert breakdown["severityAndImpactContext"] == 0
        assert breakdown["softwareIdentification"] == 0
        assert breakdown["patchinfo"] == 0
    
    def test_score_invalid_cve(self):
        """Test scoring an invalid CVE record."""
        invalid_cve = {"invalid": "data"}
        result = score_cve_record(invalid_cve)
        
        assert result["totalScore"] == 0
        assert result["assigningCna"] == "Unknown"
        assert all(score == 0 for score in result["scoreBreakdown"].values())
    
    def test_score_cve_missing_metadata(self):
        """Test scoring CVE with missing metadata."""
        cve_no_metadata = {
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "shortName": "TestCNA"
                    }
                }
            }
        }
        result = score_cve_record(cve_no_metadata)
        
        assert result["cveId"] == ""
        assert result["datePublished"] == ""
        assert result["assigningCna"] == "TestCNA"


class TestFoundationalCompleteness(TestScoringFixtures):
    """Test foundational completeness scoring."""
    
    def test_complete_foundational_fields(self, sample_cve_complete):
        """Test with all foundational fields present."""
        cna = sample_cve_complete["containers"]["cna"]
        score = _calculate_foundational_completeness(sample_cve_complete, cna)
        assert score == 50
    
    def test_missing_foundational_fields(self):
        """Test with missing foundational fields."""
        cve = {}
        cna = {
            "descriptions": ["test"],
            "affected": ["test"]
            # Missing references
        }
        score = _calculate_foundational_completeness(cve, cna)
        assert score == 0
    
    def test_empty_foundational_fields(self):
        """Test with empty foundational fields."""
        cve = {}
        cna = {
            "descriptions": [],
            "affected": [],
            "references": []
        }
        score = _calculate_foundational_completeness(cve, cna)
        assert score == 0


class TestRootCauseAnalysis(TestScoringFixtures):
    """Test root cause analysis scoring."""
    
    def test_valid_cwe_scoring(self, sample_cve_complete):
        """Test with valid CWE identifier."""
        cna = sample_cve_complete["containers"]["cna"]
        score = _calculate_root_cause_analysis(sample_cve_complete, cna)
        assert score == 15
    
    def test_invalid_cwe_scoring(self):
        """Test with invalid CWE identifier."""
        cve = {}
        cna = {
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "cweId": "CWE-99999",  # Invalid CWE
                            "description": "Invalid CWE"
                        }
                    ]
                }
            ]
        }
        score = _calculate_root_cause_analysis(cve, cna)
        assert score == 0
    
    def test_no_problem_types(self):
        """Test with no problem types."""
        cve = {}
        cna = {}
        score = _calculate_root_cause_analysis(cve, cna)
        assert score == 0
    
    def test_find_valid_cwe_success(self):
        """Test finding valid CWE in problem types."""
        problem_types = [
            {
                "descriptions": [
                    {
                        "cweId": "CWE-78",
                        "description": "OS Command Injection"
                    }
                ]
            }
        ]
        assert _find_valid_cwe(problem_types) is True
    
    def test_find_valid_cwe_failure(self):
        """Test not finding valid CWE in problem types."""
        problem_types = [
            {
                "descriptions": [
                    {
                        "description": "Some vulnerability"
                    }
                ]
            }
        ]
        assert _find_valid_cwe(problem_types) is False
    
    def test_is_valid_cwe_id_formats(self):
        """Test CWE ID validation with different formats."""
        assert _is_valid_cwe_id("CWE-78") is True
        assert _is_valid_cwe_id("78") is True
        assert _is_valid_cwe_id("CWE-99999") is False
        assert _is_valid_cwe_id("") is False
        assert _is_valid_cwe_id("invalid") is False


class TestSeverityContext(TestScoringFixtures):
    """Test severity and impact context scoring."""
    
    def test_valid_cvss_scoring(self, sample_cve_complete):
        """Test with valid CVSS metrics."""
        cna = sample_cve_complete["containers"]["cna"]
        score = _calculate_severity_context(sample_cve_complete, cna)
        assert score == 15
    
    def test_no_metrics(self):
        """Test with no metrics."""
        cve = {}
        cna = {}
        score = _calculate_severity_context(cve, cna)
        assert score == 0
    
    def test_cvss_without_vector(self):
        """Test CVSS metrics without vector string."""
        cve = {}
        cna = {
            "metrics": [
                {
                    "cvssV3_1": {
                        "baseScore": 9.8
                        # Missing vectorString
                    }
                }
            ]
        }
        score = _calculate_severity_context(cve, cna)
        assert score == 0
    
    def test_has_cvss_metrics_detection(self):
        """Test CVSS metrics detection."""
        metrics_with_cvss = [
            {"cvssV3_1": {"baseScore": 9.8}}
        ]
        metrics_without_cvss = [
            {"other": "data"}
        ]
        
        assert _has_cvss_metrics(metrics_with_cvss) is True
        assert _has_cvss_metrics(metrics_without_cvss) is False
        assert _has_cvss_metrics([]) is False
    
    def test_has_valid_cvss_vector_detection(self):
        """Test CVSS vector string detection."""
        metrics_with_vector = [
            {
                "cvssV3_1": {
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            }
        ]
        metrics_without_vector = [
            {
                "cvssV3_1": {
                    "baseScore": 9.8
                }
            }
        ]
        
        assert _has_valid_cvss_vector(metrics_with_vector) is True
        assert _has_valid_cvss_vector(metrics_without_vector) is False


class TestSoftwareIdentification(TestScoringFixtures):
    """Test software identification scoring."""
    
    def test_valid_cpe_scoring(self, sample_cve_complete):
        """Test with valid CPE identifiers."""
        cna = sample_cve_complete["containers"]["cna"]
        score = _calculate_software_identification(sample_cve_complete, cna)
        assert score == 10
    
    def test_no_affected_products(self):
        """Test with no affected products."""
        cve = {}
        cna = {}
        score = _calculate_software_identification(cve, cna)
        assert score == 0
    
    def test_affected_without_cpes(self):
        """Test affected products without CPEs."""
        cve = {}
        cna = {
            "affected": [
                {
                    "vendor": "TestVendor",
                    "product": "TestProduct"
                    # Missing cpes
                }
            ]
        }
        score = _calculate_software_identification(cve, cna)
        assert score == 0
    
    def test_has_cpe_identifiers_detection(self):
        """Test CPE identifier detection."""
        affected_with_cpes = [
            {
                "cpes": ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
            }
        ]
        affected_without_cpes = [
            {
                "vendor": "TestVendor"
            }
        ]
        
        assert _has_cpe_identifiers(affected_with_cpes) is True
        assert _has_cpe_identifiers(affected_without_cpes) is False
        assert _has_cpe_identifiers([]) is False


class TestActionableIntelligence(TestScoringFixtures):
    """Test actionable intelligence/patch info scoring."""
    
    def test_valid_patch_reference_scoring(self, sample_cve_complete):
        """Test with valid patch references."""
        cna = sample_cve_complete["containers"]["cna"]
        score = _calculate_actionable_intelligence(sample_cve_complete, cna)
        assert score == 10
    
    def test_no_references(self):
        """Test with no references."""
        cve = {}
        cna = {}
        score = _calculate_actionable_intelligence(cve, cna)
        assert score == 0
    
    def test_references_without_patch_tags(self):
        """Test references without patch tags."""
        cve = {}
        cna = {
            "references": [
                {
                    "url": "https://example.com/info",
                    "tags": ["vendor-advisory"]
                }
            ]
        }
        score = _calculate_actionable_intelligence(cve, cna)
        assert score == 0
    
    def test_has_patch_references_detection(self):
        """Test patch reference detection."""
        refs_with_patch = [
            {
                "tags": ["patch", "vendor-advisory"]
            }
        ]
        refs_without_patch = [
            {
                "tags": ["vendor-advisory"]
            }
        ]
        
        assert _has_patch_references(refs_with_patch) is True
        assert _has_patch_references(refs_without_patch) is False
        assert _has_patch_references([]) is False


class TestScoreMultipleCves(TestScoringFixtures):
    """Test batch scoring functionality."""
    
    def test_score_multiple_cves_success(self, sample_cve_complete, sample_cve_minimal):
        """Test scoring multiple CVEs successfully."""
        cves = [sample_cve_complete, sample_cve_minimal]
        results = score_multiple_cves(cves)
        
        assert len(results) == 2
        assert results[0]["totalScore"] == 100
        assert results[1]["totalScore"] == 0
    
    def test_score_empty_list(self):
        """Test scoring empty CVE list."""
        results = score_multiple_cves([])
        assert results == []
    
    def test_score_with_failures(self, sample_cve_complete):
        """Test scoring with some failures."""
        cves = [sample_cve_complete, {"invalid": "data"}, sample_cve_complete]
        results = score_multiple_cves(cves)
        
        # Should handle invalid CVE gracefully
        assert len(results) == 3
        assert results[0]["totalScore"] == 100
        assert results[1]["totalScore"] == 0  # Invalid CVE gets zero score
        assert results[2]["totalScore"] == 100


class TestScoringConfiguration:
    """Test scoring configuration and setup."""
    
    def test_scoring_config_usage(self):
        """Test that scoring functions use configuration properly."""
        # Test with actual config instead of mocking
        cve = {}
        cna = {
            "descriptions": ["test"],
            "affected": ["test"],
            "references": ["test"]
        }
        
        score = _calculate_foundational_completeness(cve, cna)
        # Just verify that the function returns a valid score
        assert isinstance(score, (int, float))
        assert score >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
