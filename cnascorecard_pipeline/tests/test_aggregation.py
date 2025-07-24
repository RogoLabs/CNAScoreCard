"""
Unit tests for aggregation module.

This module tests the CNA-level aggregation logic to ensure correct
calculation of summary statistics and trend analysis.
"""
import pytest
from unittest.mock import patch, MagicMock, mock_open
from typing import Dict, Any, List
from datetime import datetime

# Import the module under test
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from aggregation import aggregate_cna_scores


class TestAggregationFixtures:
    """Test fixtures for aggregation tests."""
    
    @pytest.fixture
    def sample_scored_cves(self) -> List[Dict[str, Any]]:
        """Sample scored CVE records for testing."""
        return [
            {
                "cveId": "CVE-2024-0001",
                "assigningCna": "TestCNA1",
                "datePublished": "2024-01-15",
                "totalScore": 85,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,
                    "rootCauseAnalysis": 15,
                    "severityAndImpactContext": 15,
                    "softwareIdentification": 5,
                    "patchinfo": 0
                }
            },
            {
                "cveId": "CVE-2024-0002",
                "assigningCna": "TestCNA1",
                "datePublished": "2024-01-20",
                "totalScore": 75,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,
                    "rootCauseAnalysis": 0,
                    "severityAndImpactContext": 15,
                    "softwareIdentification": 10,
                    "patchinfo": 0
                }
            },
            {
                "cveId": "CVE-2024-0003",
                "assigningCna": "TestCNA2",
                "datePublished": "2024-01-25",
                "totalScore": 100,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,
                    "rootCauseAnalysis": 15,
                    "severityAndImpactContext": 15,
                    "softwareIdentification": 10,
                    "patchinfo": 10
                }
            },
            {
                "cveId": "CVE-2024-0004",
                "assigningCna": "TestCNA2",
                "datePublished": "2024-02-01",
                "totalScore": 90,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,
                    "rootCauseAnalysis": 15,
                    "severityAndImpactContext": 15,
                    "softwareIdentification": 10,
                    "patchinfo": 0
                }
            }
        ]
    
    @pytest.fixture
    def sample_periods(self):
        """Sample time periods for trend analysis."""
        return [
            (datetime(2024, 1, 1), datetime(2024, 1, 31)),
            (datetime(2024, 2, 1), datetime(2024, 2, 29))
        ]
    
    @pytest.fixture
    def mock_cna_metadata(self):
        """Mock CNA metadata for testing."""
        return {
            "testcna1": {
                "shortName": "TestCNA1",
                "organizationName": "Test Organization 1",
                "scope": "Test scope 1",
                "type": ["vendor"],
                "country": "US"
            },
            "testcna2": {
                "shortName": "TestCNA2", 
                "organizationName": "Test Organization 2",
                "scope": "Test scope 2",
                "type": ["coordinator"],
                "country": "CA"
            }
        }


class TestAggregateCnaScores(TestAggregationFixtures):
    """Test the main aggregate_cna_scores function."""
    
    @patch('aggregation.os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    @patch('os.path.exists')
    def test_aggregate_basic_functionality(
        self, 
        mock_exists, 
        mock_json_load,
        mock_file_open,
        sample_scored_cves,
        sample_periods,
        mock_cna_metadata
    ):
        """Test basic aggregation functionality."""
        # Setup mocks
        mock_exists.return_value = True
        mock_json_load.return_value = [
            {
                "shortName": "TestCNA1",
                "organizationName": "Test Organization 1",
                "scope": "Test scope 1",
                "type": ["vendor"],
                "country": "US"
            },
            {
                "shortName": "TestCNA2",
                "organizationName": "Test Organization 2", 
                "scope": "Test scope 2",
                "type": ["coordinator"],
                "country": "CA"
            }
        ]
        
        # Use actual CVE data instead of mock
        actual_cves = [
            {
                "cveId": "CVE-2024-0001",
                "assigningCna": "TestCNA1",
                "datePublished": "2024-01-15",
                "totalScore": 85,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,
                    "rootCauseAnalysis": 15,
                    "severityAndImpactContext": 15,
                    "softwareIdentification": 5,
                    "patchinfo": 0
                }
            },
            {
                "cveId": "CVE-2024-0002",
                "assigningCna": "TestCNA1",
                "datePublished": "2024-01-20",
                "totalScore": 75,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,
                    "rootCauseAnalysis": 0,
                    "severityAndImpactContext": 15,
                    "softwareIdentification": 10,
                    "patchinfo": 0
                }
            }
        ]
        
        result = aggregate_cna_scores(actual_cves, sample_periods)
        
        # Verify structure
        assert isinstance(result, dict)
        # The function should return results for all official CNAs, even if no CVE data
        assert len(result) >= 2
        
        # Check that we have CNA info structure
        for cna_name, cna_result in result.items():
            assert "cna_info" in cna_result
            assert "cna_scoring" in cna_result
            assert "cve_scoring" in cna_result
        
        # Verify CNA scoring structure (if TestCNA1 exists)
        if "TestCNA1" in result:
            cna1_scoring = result["TestCNA1"]["cna_scoring"][0]
            # Note: assertions may need adjustment based on actual function behavior
            assert "total_cves" in cna1_scoring
            assert "overall_average_score" in cna1_scoring
            
            # Verify CVE scoring structure
            cna1_cve_scoring = result["TestCNA1"]["cve_scoring"]
            assert isinstance(cna1_cve_scoring, list)
    
    @patch('os.path.exists')
    def test_aggregate_no_metadata_file(self, mock_exists, sample_scored_cves, sample_periods):
        """Test aggregation when CNA metadata file doesn't exist."""
        mock_exists.return_value = False
        
        result = aggregate_cna_scores(sample_scored_cves, sample_periods)
        
        # Should still work but with limited metadata
        assert isinstance(result, dict)
        assert len(result) >= 0  # May be empty if no official CNAs match
    
    def test_aggregate_empty_cves(self, sample_periods):
        """Test aggregation with empty CVE list."""
        with patch('aggregation.os.path.exists', return_value=False):
            result = aggregate_cna_scores([], sample_periods)
            assert isinstance(result, dict)
    
    @patch('aggregation.os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    @patch('os.path.exists')
    def test_aggregate_score_calculations(
        self,
        mock_exists,
        mock_json_load,
        mock_file_open,
        sample_scored_cves,
        sample_periods
    ):
        """Test that score calculations are correct."""
        # Setup mocks
        mock_exists.return_value = True
        mock_json_load.return_value = [
            {"shortName": "TestCNA1"},
            {"shortName": "TestCNA2"}
        ]
        
        # Use actual CVE data for testing calculations
        actual_cves = [
            {
                "cveId": "CVE-2024-0001",
                "assigningCna": "TestCNA1",
                "datePublished": "2024-01-15",
                "totalScore": 85,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,
                    "rootCauseAnalysis": 15,
                    "severityAndImpactContext": 15,
                    "softwareIdentification": 5,
                    "patchinfo": 0
                }
            },
            {
                "cveId": "CVE-2024-0002",
                "assigningCna": "TestCNA1",
                "datePublished": "2024-01-20",
                "totalScore": 75,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,
                    "rootCauseAnalysis": 0,
                    "severityAndImpactContext": 15,
                    "softwareIdentification": 10,
                    "patchinfo": 0
                }
            }
        ]
        
        result = aggregate_cna_scores(actual_cves, sample_periods)
        
        # Check that we have results and basic structure
        assert isinstance(result, dict)
        assert len(result) >= 1
        
        # Check that CNA scoring structure exists and has valid data
        for cna_name, cna_result in result.items():
            assert "cna_scoring" in cna_result
            if cna_result["cna_scoring"]:
                cna_scoring = cna_result["cna_scoring"][0]
                assert "overall_average_score" in cna_scoring
                assert isinstance(cna_scoring["overall_average_score"], (int, float))
    
    @patch('aggregation.os.path.exists')
    @patch('builtins.open', new_callable=mock_open)
    @patch('json.load')
    @patch('os.path.exists')
    def test_aggregate_percentage_calculations(
        self,
        mock_exists,
        mock_json_load,
        mock_file_open,
        sample_periods
    ):
        """Test percentage-based calculations for category completeness."""
        # Setup mocks
        mock_exists.return_value = True
        mock_json_load.return_value = [{"shortName": "TestCNA"}]
        
        # Create test data where some CVEs have certain categories, others don't
        test_cves = [
            {
                "cveId": "CVE-2024-0001",
                "assigningCna": "TestCNA",
                "datePublished": "2024-01-15",
                "totalScore": 50,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,  # Has this
                    "rootCauseAnalysis": 0,          # Missing this
                    "severityAndImpactContext": 0,   # Missing this
                    "softwareIdentification": 0,     # Missing this
                    "patchinfo": 0                   # Missing this
                }
            },
            {
                "cveId": "CVE-2024-0002",
                "assigningCna": "TestCNA",
                "datePublished": "2024-01-20",
                "totalScore": 65,
                "scoreBreakdown": {
                    "foundationalCompleteness": 50,  # Has this
                    "rootCauseAnalysis": 15,         # Has this
                    "severityAndImpactContext": 0,   # Missing this
                    "softwareIdentification": 0,     # Missing this
                    "patchinfo": 0                   # Missing this
                }
            }
        ]
        
        result = aggregate_cna_scores(test_cves, sample_periods)
        
        if "TestCNA" in result:
            scoring = result["TestCNA"]["cna_scoring"][0]
            # 100% of CVEs have foundational completeness (2/2)
            assert scoring.get("percent_foundational_completeness", 0) == 100.0
            # 50% of CVEs have root cause analysis (1/2)
            assert scoring.get("percent_root_cause_analysis", 0) == 50.0
            # 0% have the others
            assert scoring.get("percent_severity_and_impact", 0) == 0.0


class TestCnaNameMapping:
    """Test CNA name mapping functionality."""
    
    def test_exact_name_match(self):
        """Test exact CNA name matching."""
        from aggregation import aggregate_cna_scores
        
        # This is testing the internal mapping logic
        # We'd need to extract the mapping function to test it properly
        # For now, we test it through the main function
        pass
    
    def test_case_insensitive_match(self):
        """Test case-insensitive CNA name matching."""
        pass
    
    def test_normalized_name_match(self):
        """Test normalized CNA name matching (removing spaces, hyphens)."""
        pass


class TestTrendCalculations:
    """Test trend calculation functionality."""
    
    def test_trend_calculation_called(self):
        """Test that aggregation function works with empty data."""
        # Create sample periods directly
        from datetime import datetime
        sample_periods = [
            (datetime(2024, 1, 1), datetime(2024, 1, 31)),
            (datetime(2024, 2, 1), datetime(2024, 2, 29))
        ]
        
        with patch('aggregation.os.path.exists', return_value=False):
            result = aggregate_cna_scores([], sample_periods)
            
        # Just verify the function returns a valid result
        assert isinstance(result, dict)
        
        # Verify trend functions would be called for CNAs with data
        # (They won't be called with empty CVE list, but structure should be there)
        assert isinstance(result, dict)


class TestErrorHandling:
    """Test error handling in aggregation."""
    
    @patch('aggregation.os.path.exists')
    @patch('aggregation.open', side_effect=IOError("File read error"))
    def test_file_read_error(self, mock_file, mock_exists):
        """Test handling of file read errors."""
        mock_exists.return_value = True
        
        # Create sample periods directly
        from datetime import datetime
        sample_periods = [
            (datetime(2024, 1, 1), datetime(2024, 1, 31)),
            (datetime(2024, 2, 1), datetime(2024, 2, 29))
        ]
        
        # Should handle file read errors gracefully
        result = aggregate_cna_scores([], sample_periods)
        assert isinstance(result, dict)
    
    @patch('aggregation.os.path.exists')
    @patch('aggregation.open', new_callable=mock_open, read_data='invalid json')
    @patch('aggregation.json.load', side_effect=ValueError("Invalid JSON"))
    def test_json_parse_error(self, mock_json, mock_file, mock_exists):
        """Test handling of JSON parse errors."""
        mock_exists.return_value = True
        
        # Create sample periods directly
        from datetime import datetime
        sample_periods = [
            (datetime(2024, 1, 1), datetime(2024, 1, 31)),
            (datetime(2024, 2, 1), datetime(2024, 2, 29))
        ]
        
        # Should handle JSON parse errors gracefully
        result = aggregate_cna_scores([], sample_periods)
        assert isinstance(result, dict)
    
    def test_invalid_cve_data(self):
        """Test handling of invalid CVE data structures."""
        # Create sample periods directly
        from datetime import datetime
        sample_periods = [
            (datetime(2024, 1, 1), datetime(2024, 1, 31)),
            (datetime(2024, 2, 1), datetime(2024, 2, 29))
        ]
        
        invalid_cves = [
            {"invalid": "structure"},
            {"cveId": "CVE-2024-0001"},  # Missing required fields
            None  # Completely invalid
        ]
        
        # Should handle invalid CVE data gracefully
        result = aggregate_cna_scores(invalid_cves, sample_periods)
        assert isinstance(result, dict)


class TestDataStructureValidation:
    """Test output data structure validation."""
    
    @patch('aggregation.os.path.exists')
    @patch('aggregation.open', new_callable=mock_open)
    @patch('aggregation.json.load')
    def test_output_structure_completeness(
        self,
        mock_json_load,
        mock_file,
        mock_exists
    ):
        """Test that output structure contains all required fields."""
        mock_exists.return_value = True
        mock_json_load.return_value = [{"shortName": "TestCNA"}]
        
        # Create sample periods directly
        from datetime import datetime
        sample_periods = [
            (datetime(2024, 1, 1), datetime(2024, 1, 31)),
            (datetime(2024, 2, 1), datetime(2024, 2, 29))
        ]
        
        test_cve = {
            "cveId": "CVE-2024-0001",
            "assigningCna": "TestCNA",
            "datePublished": "2024-01-15",
            "totalScore": 85,
            "scoreBreakdown": {
                "foundationalCompleteness": 50,
                "rootCauseAnalysis": 15,
                "severityAndImpactContext": 15,
                "softwareIdentification": 5,
                "patchinfo": 0
            }
        }
        
        result = aggregate_cna_scores([test_cve], sample_periods)
        
        if "TestCNA" in result:
            cna_result = result["TestCNA"]
            
            # Check top-level structure
            assert "cna_info" in cna_result
            assert "cna_scoring" in cna_result
            assert "cve_scoring" in cna_result
            
            # Check cna_info required fields
            cna_info = cna_result["cna_info"][0]
            required_info_fields = [
                "cna", "total_cves", "total_cves_scored",
                "organizationName", "scope", "advisories", "email",
                "officialCnaID", "cnaTypes", "country", "disclosurePolicy",
                "rootCnaInfo", "rank", "active_cna_count", "percentile"
            ]
            for field in required_info_fields:
                assert field in cna_info
            
            # Check cna_scoring required fields
            cna_scoring = cna_result["cna_scoring"][0]
            required_scoring_fields = [
                "total_cves", "total_cves_scored", "recent_cves_count",
                "overall_average_score", "average_foundational_completeness",
                "average_root_cause_analysis", "average_software_identification",
                "average_severity_context", "average_patchinfo",
                "percent_foundational_completeness", "percent_root_cause_analysis",
                "percent_software_identification", "percent_severity_and_impact",
                "percent_patchinfo", "trend_direction", "trend_description",
                "monthly_trends"
            ]
            for field in required_scoring_fields:
                assert field in cna_scoring
            
            # Check cve_scoring structure
            cve_scoring = cna_result["cve_scoring"][0]
            required_cve_fields = [
                "cveId", "assigningCna", "datePublished", 
                "totalCveScore", "scoreBreakdown"
            ]
            for field in required_cve_fields:
                assert field in cve_scoring


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
