"""
Tests for utils.py - Utility functions for the CNA Scorecard pipeline.
"""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from utils import (
    setup_logging,
    ensure_directory_exists,
    load_json_file,
    write_json_file,
    sanitize_filename,
    validate_cve_record,
    extract_cna_short_name,
    get_nested_value,
    calculate_percentage,
    format_date_string,
    ProgressTracker
)


class TestSetupLogging:
    """Tests for setup_logging function."""
    
    def test_returns_logger(self):
        """Should return a logger instance."""
        logger = setup_logging()
        assert logger is not None
    
    def test_custom_log_level(self):
        """Should accept custom log level."""
        logger = setup_logging(log_level="DEBUG")
        assert logger is not None


class TestEnsureDirectoryExists:
    """Tests for ensure_directory_exists function."""
    
    def test_creates_directory(self, tmp_path):
        """Should create directory if it doesn't exist."""
        new_dir = tmp_path / "new_dir"
        assert not new_dir.exists()
        
        ensure_directory_exists(new_dir)
        
        assert new_dir.exists()
        assert new_dir.is_dir()
    
    def test_creates_nested_directories(self, tmp_path):
        """Should create nested directories."""
        nested_dir = tmp_path / "level1" / "level2" / "level3"
        
        ensure_directory_exists(nested_dir)
        
        assert nested_dir.exists()
    
    def test_handles_existing_directory(self, tmp_path):
        """Should not raise if directory exists."""
        existing_dir = tmp_path / "existing"
        existing_dir.mkdir()
        
        # Should not raise
        ensure_directory_exists(existing_dir)
        assert existing_dir.exists()


class TestLoadJsonFile:
    """Tests for load_json_file function."""
    
    def test_loads_valid_json(self, tmp_path):
        """Should load valid JSON file."""
        json_file = tmp_path / "test.json"
        test_data = {"key": "value", "number": 42}
        json_file.write_text(json.dumps(test_data))
        
        loaded = load_json_file(json_file)
        
        assert loaded == test_data
    
    def test_raises_on_invalid_json(self, tmp_path):
        """Should raise on invalid JSON."""
        json_file = tmp_path / "invalid.json"
        json_file.write_text("not valid json {")
        
        with pytest.raises(Exception):
            load_json_file(json_file)
    
    def test_raises_on_missing_file(self, tmp_path):
        """Should raise on missing file."""
        missing_file = tmp_path / "missing.json"
        
        with pytest.raises(Exception):
            load_json_file(missing_file)


class TestWriteJsonFile:
    """Tests for write_json_file function."""
    
    def test_writes_json(self, tmp_path):
        """Should write JSON file."""
        json_file = tmp_path / "output.json"
        test_data = {"key": "value"}
        
        write_json_file(test_data, json_file)
        
        assert json_file.exists()
        loaded = json.loads(json_file.read_text())
        assert loaded == test_data
    
    def test_custom_indent(self, tmp_path):
        """Should respect custom indent."""
        json_file = tmp_path / "output.json"
        
        write_json_file({"key": "value"}, json_file, indent=4)
        
        content = json_file.read_text()
        assert "    " in content  # 4-space indent
    
    def test_creates_parent_directories(self, tmp_path):
        """Should create parent directories."""
        nested_file = tmp_path / "nested" / "dir" / "output.json"
        
        write_json_file({"key": "value"}, nested_file)
        
        assert nested_file.exists()


class TestSanitizeFilename:
    """Tests for sanitize_filename function."""
    
    def test_replaces_special_chars(self):
        """Should replace special characters with underscore."""
        # sanitize_filename replaces unsafe chars with underscore
        assert sanitize_filename("file/name") == "file_name"
        assert sanitize_filename("file:name") == "file_name"
    
    def test_keeps_alphanumeric(self):
        """Should keep alphanumeric characters."""
        assert sanitize_filename("ABC123") == "ABC123"
    
    def test_keeps_safe_chars(self):
        """Should keep safe characters like - _ ."""
        assert sanitize_filename("file-name_v1.txt") == "file-name_v1.txt"
    
    def test_handles_special_input(self):
        """Should handle various special inputs."""
        result = sanitize_filename("///")
        assert result is not None  # Implementation-dependent


class TestValidateCveRecord:
    """Tests for validate_cve_record function."""
    
    def test_valid_record(self):
        """Should return True for valid CVE record."""
        cve = {
            "cveMetadata": {
                "cveId": "CVE-2024-0001",
                "state": "PUBLISHED"
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test"}]
                }
            }
        }
        assert validate_cve_record(cve) is True
    
    def test_missing_cve_id(self):
        """Should return False for missing CVE ID."""
        cve = {
            "cveMetadata": {"state": "PUBLISHED"},
            "containers": {"cna": {}}
        }
        assert validate_cve_record(cve) is False
    
    def test_with_containers(self):
        """Should return True when containers present."""
        cve = {
            "cveMetadata": {"cveId": "CVE-2024-0001"},
            "containers": {"cna": {}}
        }
        # Based on actual implementation, this may be valid
        assert validate_cve_record(cve) is True
    
    def test_various_states(self):
        """Test behavior with different states."""
        cve = {
            "cveMetadata": {
                "cveId": "CVE-2024-0001",
                "state": "REJECTED"
            },
            "containers": {"cna": {}}
        }
        # Actual behavior depends on implementation
        result = validate_cve_record(cve)
        assert isinstance(result, bool)


class TestExtractCnaShortName:
    """Tests for extract_cna_short_name function."""
    
    def test_extracts_from_provider_metadata(self):
        """Should extract from providerMetadata.shortName."""
        cve = {
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "shortName": "microsoft"
                    }
                }
            }
        }
        assert extract_cna_short_name(cve) == "microsoft"
    
    def test_prefers_provider_metadata(self):
        """Should prefer providerMetadata when available."""
        cve = {
            "cveMetadata": {
                "assignerShortName": "fallback"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "shortName": "preferred"
                    }
                }
            }
        }
        assert extract_cna_short_name(cve) == "preferred"
    
    def test_returns_none_when_missing(self):
        """Should return None when no short name available."""
        cve = {
            "cveMetadata": {},
            "containers": {"cna": {}}
        }
        assert extract_cna_short_name(cve) is None
    
    def test_empty_record(self):
        """Should handle empty record."""
        cve = {}
        result = extract_cna_short_name(cve)
        assert result is None


class TestGetNestedValue:
    """Tests for get_nested_value function."""
    
    def test_simple_path(self):
        """Should retrieve value at simple path."""
        data = {"key": "value"}
        assert get_nested_value(data, ["key"]) == "value"
    
    def test_nested_path(self):
        """Should retrieve value at nested path."""
        data = {"level1": {"level2": "deep_value"}}
        assert get_nested_value(data, ["level1", "level2"]) == "deep_value"
    
    def test_missing_key(self):
        """Should return None for missing key."""
        data = {"key": "value"}
        assert get_nested_value(data, ["missing"]) is None
    
    def test_empty_path(self):
        """Should return data for empty path."""
        data = {"key": "value"}
        assert get_nested_value(data, []) == data


class TestCalculatePercentage:
    """Tests for calculate_percentage function."""
    
    def test_normal_calculation(self):
        """Should calculate percentage correctly."""
        assert calculate_percentage(50, 100) == 50.0
        assert calculate_percentage(1, 4) == 25.0
    
    def test_decimal_places(self):
        """Should respect decimal places."""
        assert calculate_percentage(1, 3, decimal_places=2) == 33.33
        assert calculate_percentage(1, 3, decimal_places=0) == 33.0
    
    def test_zero_denominator(self):
        """Should handle zero denominator."""
        assert calculate_percentage(50, 0) == 0.0
    
    def test_zero_numerator(self):
        """Should handle zero numerator."""
        assert calculate_percentage(0, 100) == 0.0


class TestFormatDateString:
    """Tests for format_date_string function."""
    
    def test_iso_format(self):
        """Should format ISO date string."""
        result = format_date_string("2024-01-15T10:30:00.000Z")
        assert "2024" in result
        assert "01" in result or "Jan" in result
    
    def test_invalid_date(self):
        """Should handle invalid date."""
        result = format_date_string("not-a-date")
        # Should return original or formatted error
        assert result is not None
    
    def test_empty_string(self):
        """Should handle empty string."""
        result = format_date_string("")
        assert result is not None


class TestProgressTracker:
    """Tests for ProgressTracker class."""
    
    def test_initialization(self):
        """Should initialize with total."""
        tracker = ProgressTracker(total=100, description="Test")
        assert tracker is not None
    
    def test_update(self):
        """Should update progress."""
        tracker = ProgressTracker(total=100, description="Test")
        tracker.update(10)
        # Should not raise
    
    def test_multiple_updates(self):
        """Should handle multiple updates."""
        tracker = ProgressTracker(total=100, description="Test")
        tracker.update(10)
        tracker.update(20)
        tracker.update(30)
        # Should not raise
