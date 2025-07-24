"""
Unit tests for ingest module.

This module tests the CVE data loading and CNA extraction functionality
to ensure correct data ingestion from the filesystem.
"""
import pytest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

# Import the module under test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from ingest import (
    load_cve_records,
    load_cna_list,
    get_date_range_for_period,
    validate_date_range,
    _get_cve_file_list,
    _get_year_directories,
    _get_year_files,
    _load_and_filter_cves,
    _load_single_cve_file,
    _passes_date_filter
)


class TestIngestFixtures:
    """Test fixtures for ingest tests."""
    
    @pytest.fixture
    def sample_cve_valid(self) -> Dict[str, Any]:
        """Valid CVE record for testing."""
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
                            "value": "Test vulnerability description"
                        }
                    ]
                }
            }
        }
    
    @pytest.fixture
    def sample_cve_rejected(self) -> Dict[str, Any]:
        """Rejected CVE record for testing."""
        return {
            "cveId": "CVE-2024-67890",
            "cveMetadata": {
                "cveId": "CVE-2024-67890",
                "datePublished": "2024-01-15T10:00:00.000Z",
                "state": "REJECTED"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "shortName": "TestCNA"
                    }
                }
            }
        }
    
    @pytest.fixture
    def sample_cve_invalid(self) -> Dict[str, Any]:
        """Invalid CVE record for testing."""
        return {
            "invalid": "data",
            "no_metadata": True
        }
    
    @pytest.fixture
    def mock_cve_files(self):
        """Mock CVE file paths."""
        return [
            "/path/to/cves/2024/CVE-2024-0001.json",
            "/path/to/cves/2024/CVE-2024-0002.json",
            "/path/to/cves/2025/CVE-2025-0001.json"
        ]


class TestLoadCveRecords(TestIngestFixtures):
    """Test the main load_cve_records function."""
    
    @patch('ingest._load_and_filter_cves')
    @patch('ingest._get_cve_file_list')
    def test_load_cve_records_basic(
        self, 
        mock_get_files, 
        mock_load_filter,
        mock_cve_files,
        sample_cve_valid
    ):
        """Test basic CVE record loading."""
        mock_get_files.return_value = mock_cve_files
        mock_load_filter.return_value = [sample_cve_valid]
        
        result = load_cve_records()
        
        assert len(result) == 1
        assert result[0]["cveId"] == "CVE-2024-12345"
        mock_get_files.assert_called_once()
        mock_load_filter.assert_called_once()
    
    @patch('ingest._load_and_filter_cves')
    @patch('ingest._get_cve_file_list')
    def test_load_cve_records_with_dates(
        self, 
        mock_get_files, 
        mock_load_filter,
        mock_cve_files,
        sample_cve_valid
    ):
        """Test CVE record loading with date filtering."""
        mock_get_files.return_value = mock_cve_files
        mock_load_filter.return_value = [sample_cve_valid]
        
        result = load_cve_records(
            start_date="2024-01-01", 
            end_date="2024-12-31"
        )
        
        assert len(result) == 1
        mock_get_files.assert_called_with(
            str(Path(__file__).parent.parent.parent / "cve_data"),
            "2024-01-01",
            "2024-12-31"
        )
    
    @patch('ingest._get_cve_file_list')
    def test_load_cve_records_no_files(self, mock_get_files):
        """Test loading when no CVE files found."""
        mock_get_files.return_value = []
        
        result = load_cve_records()
        
        assert result == []
    
    @patch('ingest._load_and_filter_cves')
    @patch('ingest._get_cve_file_list')
    def test_load_cve_records_custom_dir(
        self, 
        mock_get_files, 
        mock_load_filter,
        sample_cve_valid
    ):
        """Test loading from custom directory."""
        custom_dir = "/custom/cve/path"
        mock_get_files.return_value = ["/custom/file.json"]
        mock_load_filter.return_value = [sample_cve_valid]
        
        result = load_cve_records(cve_dir=custom_dir)
        
        assert len(result) == 1
        mock_get_files.assert_called_with(custom_dir, None, None)


class TestGetCveFileList(TestIngestFixtures):
    """Test CVE file list generation."""
    
    @patch('ingest._get_year_files')
    @patch('ingest._get_year_directories')
    @patch('pathlib.Path.exists')
    def test_get_cve_file_list_with_dates(
        self, 
        mock_exists, 
        mock_year_dirs, 
        mock_year_files
    ):
        """Test file list generation with date filtering."""
        mock_exists.return_value = True
        mock_year_dirs.return_value = ['2023', '2024', '2025']
        mock_year_files.return_value = ['/path/file1.json', '/path/file2.json']
        
        result = _get_cve_file_list("/test/dir", "2024-01-01", "2024-12-31")
        
        # Should get files from all years when date filtering
        assert len(result) == 6  # 3 years × 2 files each
        mock_year_dirs.assert_called_once()
        assert mock_year_files.call_count == 3
    
    @patch('ingest._get_year_files')
    @patch('pathlib.Path.exists')
    def test_get_cve_file_list_no_dates(self, mock_exists, mock_year_files):
        """Test file list generation without date filtering."""
        mock_exists.return_value = True
        mock_year_files.return_value = ['/path/file.json']
        
        result = _get_cve_file_list("/test/dir", None, None)
        
        # Should only check recent years (2024, 2025)
        assert len(result) == 2  # 2 recent years × 1 file each
        assert mock_year_files.call_count == 2
    
    @patch('pathlib.Path.exists')
    def test_get_cve_file_list_no_directory(self, mock_exists):
        """Test file list generation when directory doesn't exist."""
        mock_exists.return_value = False
        
        result = _get_cve_file_list("/nonexistent/dir", None, None)
        
        assert result == []


class TestGetYearDirectories:
    """Test year directory listing."""
    
    @patch('pathlib.Path.iterdir')
    def test_get_year_directories_success(self, mock_iterdir):
        """Test successful year directory listing."""
        # Create mock directories with proper name attributes
        mock_2023 = MagicMock()
        mock_2023.name = '2023'
        mock_2023.is_dir.return_value = True
        
        mock_2024 = MagicMock()
        mock_2024.name = '2024'
        mock_2024.is_dir.return_value = True
        
        mock_invalid = MagicMock()
        mock_invalid.name = 'invalid'
        mock_invalid.is_dir.return_value = True
        
        mock_2025 = MagicMock()
        mock_2025.name = '2025'
        mock_2025.is_dir.return_value = True
        
        mock_file = MagicMock()
        mock_file.name = 'file.txt'
        mock_file.is_dir.return_value = False
        
        mock_dirs = [mock_2023, mock_2024, mock_invalid, mock_2025, mock_file]
        mock_iterdir.return_value = mock_dirs
        
        result = _get_year_directories(Path("/test"))
        
        # Should only return numeric directory names, sorted
        assert result == ['2023', '2024', '2025']
    
    @patch('pathlib.Path.iterdir')
    def test_get_year_directories_error(self, mock_iterdir):
        """Test year directory listing with OS error."""
        mock_iterdir.side_effect = OSError("Permission denied")
        
        result = _get_year_directories(Path("/test"))
        
        assert result == []


class TestGetYearFiles:
    """Test year file listing."""
    
    @patch('ingest.glob')
    def test_get_year_files_success(self, mock_glob):
        """Test successful year file listing."""
        expected_files = ['/path/CVE-2024-0001.json', '/path/CVE-2024-0002.json']
        mock_glob.return_value = expected_files
        
        result = _get_year_files(Path("/cves"), "2024")
        
        assert result == expected_files
        mock_glob.assert_called_once_with('/cves/2024/**/CVE-*.json', recursive=True)


class TestLoadAndFilterCves(TestIngestFixtures):
    """Test CVE loading and filtering."""
    
    @patch('ingest._load_single_cve_file')
    @patch('ingest._passes_date_filter')
    def test_load_and_filter_cves_success(
        self, 
        mock_date_filter, 
        mock_load_file,
        sample_cve_valid
    ):
        """Test successful CVE loading and filtering."""
        mock_load_file.return_value = sample_cve_valid
        mock_date_filter.return_value = True
        
        files = ['/path/file1.json', '/path/file2.json']
        result = _load_and_filter_cves(files, "2024-01-01", "2024-12-31")
        
        assert len(result) == 2
        assert mock_load_file.call_count == 2
        assert mock_date_filter.call_count == 2
    
    @patch('ingest._load_single_cve_file')
    def test_load_and_filter_cves_invalid_dates(self, mock_load_file):
        """Test CVE loading with invalid date formats."""
        mock_load_file.return_value = {}
        
        files = ['/path/file.json']
        result = _load_and_filter_cves(files, "invalid-date", "2024-12-31")
        
        assert result == []
    
    @patch('ingest._load_single_cve_file')
    @patch('ingest._passes_date_filter')
    def test_load_and_filter_cves_with_failures(
        self, 
        mock_date_filter, 
        mock_load_file,
        sample_cve_valid
    ):
        """Test CVE loading with some file failures."""
        # First file succeeds, second fails, third succeeds
        mock_load_file.side_effect = [sample_cve_valid, None, sample_cve_valid]
        mock_date_filter.return_value = True
        
        files = ['/path/file1.json', '/path/file2.json', '/path/file3.json']
        result = _load_and_filter_cves(files, None, None)
        
        assert len(result) == 2  # Only successful loads


class TestLoadSingleCveFile(TestIngestFixtures):
    """Test single CVE file loading."""
    
    @patch('ingest.load_json_file')
    @patch('ingest.validate_cve_record')
    def test_load_single_cve_file_success(
        self, 
        mock_validate, 
        mock_load_json,
        sample_cve_valid
    ):
        """Test successful single CVE file loading."""
        mock_load_json.return_value = sample_cve_valid
        mock_validate.return_value = True
        
        result = _load_single_cve_file('/path/file.json')
        
        assert result == sample_cve_valid
        mock_validate.assert_called_once_with(sample_cve_valid)
    
    @patch('ingest.load_json_file')
    @patch('ingest.validate_cve_record')
    def test_load_single_cve_file_invalid(
        self, 
        mock_validate, 
        mock_load_json,
        sample_cve_invalid
    ):
        """Test loading invalid CVE file."""
        mock_load_json.return_value = sample_cve_invalid
        mock_validate.return_value = False
        
        result = _load_single_cve_file('/path/file.json')
        
        assert result is None
    
    @patch('ingest.load_json_file')
    @patch('ingest.validate_cve_record')
    def test_load_single_cve_file_rejected(
        self, 
        mock_validate, 
        mock_load_json,
        sample_cve_rejected
    ):
        """Test loading rejected CVE file."""
        mock_load_json.return_value = sample_cve_rejected
        mock_validate.return_value = True
        
        result = _load_single_cve_file('/path/file.json')
        
        assert result is None  # Rejected CVEs should be filtered out
    
    @patch('ingest.load_json_file')
    def test_load_single_cve_file_error(self, mock_load_json):
        """Test loading CVE file with error."""
        mock_load_json.side_effect = Exception("File error")
        
        result = _load_single_cve_file('/path/file.json')
        
        assert result is None


class TestPassesDateFilter(TestIngestFixtures):
    """Test date filtering logic."""
    
    def test_passes_date_filter_no_filters(self, sample_cve_valid):
        """Test date filtering with no filters."""
        result = _passes_date_filter(sample_cve_valid, None, None)
        assert result is True
    
    def test_passes_date_filter_within_range(self, sample_cve_valid):
        """Test CVE within date range."""
        start_dt = datetime(2024, 1, 1)
        end_dt = datetime(2024, 12, 31)
        
        result = _passes_date_filter(sample_cve_valid, start_dt, end_dt)
        assert result is True
    
    def test_passes_date_filter_before_range(self, sample_cve_valid):
        """Test CVE before date range."""
        start_dt = datetime(2024, 2, 1)
        end_dt = datetime(2024, 12, 31)
        
        result = _passes_date_filter(sample_cve_valid, start_dt, end_dt)
        assert result is False
    
    def test_passes_date_filter_after_range(self, sample_cve_valid):
        """Test CVE after date range."""
        start_dt = datetime(2023, 1, 1)
        end_dt = datetime(2023, 12, 31)
        
        result = _passes_date_filter(sample_cve_valid, start_dt, end_dt)
        assert result is False
    
    def test_passes_date_filter_no_date(self):
        """Test CVE with no publication date."""
        cve_no_date = {
            "cveMetadata": {}
        }
        
        start_dt = datetime(2024, 1, 1)
        end_dt = datetime(2024, 12, 31)
        
        result = _passes_date_filter(cve_no_date, start_dt, end_dt)
        assert result is False
    
    def test_passes_date_filter_invalid_date(self):
        """Test CVE with invalid date format."""
        cve_invalid_date = {
            "cveMetadata": {
                "datePublished": "invalid-date-format"
            }
        }
        
        start_dt = datetime(2024, 1, 1)
        end_dt = datetime(2024, 12, 31)
        
        result = _passes_date_filter(cve_invalid_date, start_dt, end_dt)
        assert result is False


class TestLoadCnaList(TestIngestFixtures):
    """Test CNA list extraction."""
    
    def test_load_cna_list_success(self, sample_cve_valid):
        """Test successful CNA list extraction."""
        cves = [sample_cve_valid]
        
        result = load_cna_list(cves)
        
        assert len(result) == 1
        assert result[0]["shortName"] == "TestCNA"
    
    def test_load_cna_list_multiple_cnas(self):
        """Test CNA list extraction with multiple CNAs."""
        cves = [
            {
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "CNA1"}
                    }
                }
            },
            {
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "CNA2"}
                    }
                }
            },
            {
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "CNA1"}  # Duplicate
                    }
                }
            }
        ]
        
        result = load_cna_list(cves)
        
        assert len(result) == 2  # Duplicates should be removed
        assert {"shortName": "CNA1"} in result
        assert {"shortName": "CNA2"} in result
    
    def test_load_cna_list_empty(self):
        """Test CNA list extraction with empty input."""
        result = load_cna_list([])
        assert result == []
    
    def test_load_cna_list_invalid_cves(self):
        """Test CNA list extraction with invalid CVEs."""
        invalid_cves = [
            {"invalid": "data"},
            {"containers": {}},
            {"containers": {"cna": {}}},
            {"containers": {"cna": {"providerMetadata": {}}}}
        ]
        
        result = load_cna_list(invalid_cves)
        assert result == []


class TestDateUtilities:
    """Test date utility functions."""
    
    def test_get_date_range_for_period(self):
        """Test date range calculation."""
        # Use a simple test that doesn't rely on mocking current date
        start_date, end_date = get_date_range_for_period(6)
        
        # Just verify the format and that start_date is before end_date
        assert len(start_date) == 10  # YYYY-MM-DD format
        assert len(end_date) == 10    # YYYY-MM-DD format
        assert start_date < end_date  # Start should be before end
        assert "-" in start_date and "-" in end_date  # Contains dashes
    
    def test_validate_date_range_valid(self):
        """Test valid date range validation."""
        result = validate_date_range("2024-01-01", "2024-12-31")
        assert result is True
    
    def test_validate_date_range_invalid_order(self):
        """Test invalid date range validation (start after end)."""
        result = validate_date_range("2024-12-31", "2024-01-01")
        assert result is False
    
    def test_validate_date_range_invalid_format(self):
        """Test invalid date format validation."""
        result = validate_date_range("invalid-date", "2024-12-31")
        assert result is False


class TestIngestIntegration:
    """Integration tests for ingest module."""
    
    @patch('ingest.Path.exists')
    @patch('ingest.Path.iterdir')
    @patch('ingest.glob')
    @patch('ingest.open', new_callable=mock_open)
    @patch('ingest.load_json_file')
    def test_full_integration(
        self, 
        mock_load_json, 
        mock_file, 
        mock_glob, 
        mock_iterdir, 
        mock_exists
    ):
        """Test full integration of ingest functionality."""
        # Setup mocks
        mock_exists.return_value = True
        mock_iterdir.return_value = [
            MagicMock(name='2024', is_dir=lambda: True)
        ]
        mock_glob.return_value = ['/path/CVE-2024-0001.json']
        mock_load_json.return_value = {
            "cveId": "CVE-2024-0001",
            "cveMetadata": {
                "cveId": "CVE-2024-0001",
                "datePublished": "2024-01-15T10:00:00.000Z",
                "state": "PUBLISHED"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {"shortName": "TestCNA"}
                }
            }
        }
        
        # Test the full flow
        records = load_cve_records(
            cve_dir="/test/dir",
            start_date="2024-01-01",
            end_date="2024-12-31"
        )
        
        assert len(records) == 1
        assert records[0]["cveId"] == "CVE-2024-0001"
        
        # Test CNA extraction
        cna_list = load_cna_list(records)
        assert len(cna_list) == 1
        assert cna_list[0]["shortName"] == "TestCNA"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
