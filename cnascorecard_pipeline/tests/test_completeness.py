"""
Tests for completeness.py - Field utilization and completeness analysis.
"""
import pytest
from completeness import (
    _get_schema_fields,
    _get_nested_value,
    _custom_check,
    compute_field_utilization,
    compute_individual_cna_field_utilization
)


class TestGetSchemaFields:
    """Tests for _get_schema_fields function."""
    
    def test_returns_dict(self):
        """Should return a dictionary of field definitions."""
        fields = _get_schema_fields()
        assert isinstance(fields, dict)
    
    def test_contains_expected_fields(self):
        """Should contain key CVE schema fields."""
        fields = _get_schema_fields()
        expected_fields = [
            "dataType",
            "dataVersion", 
            "cveMetadata.cveId",
            "containers.cna.descriptions",
            "containers.cna.affected",
            "containers.cna.references",
            "containers.cna.metrics"
        ]
        for field in expected_fields:
            assert field in fields
    
    def test_field_has_path(self):
        """Each field should have a path key."""
        fields = _get_schema_fields()
        for name, info in fields.items():
            assert "path" in info, f"Field {name} missing 'path'"
            assert isinstance(info["path"], list)


class TestGetNestedValue:
    """Tests for _get_nested_value function."""
    
    def test_simple_path(self):
        """Should retrieve value at simple path."""
        data = {"key": "value"}
        assert _get_nested_value(data, ["key"]) == "value"
    
    def test_nested_path(self):
        """Should retrieve value at nested path."""
        data = {"level1": {"level2": {"level3": "deep_value"}}}
        assert _get_nested_value(data, ["level1", "level2", "level3"]) == "deep_value"
    
    def test_missing_key_returns_none(self):
        """Should return None if key is missing."""
        data = {"key": "value"}
        assert _get_nested_value(data, ["missing"]) is None
    
    def test_missing_nested_key_returns_none(self):
        """Should return None if nested key is missing."""
        data = {"level1": {"level2": "value"}}
        assert _get_nested_value(data, ["level1", "missing", "key"]) is None
    
    def test_empty_path(self):
        """Should return the data itself for empty path."""
        data = {"key": "value"}
        assert _get_nested_value(data, []) == data
    
    def test_cve_metadata_path(self):
        """Should work with CVE metadata paths."""
        cve = {
            "cveMetadata": {
                "cveId": "CVE-2024-1234",
                "assignerOrgId": "org-123"
            }
        }
        assert _get_nested_value(cve, ["cveMetadata", "cveId"]) == "CVE-2024-1234"


class TestCustomCheckDescriptions:
    """Tests for _custom_check with description checks."""
    
    def test_english_description_present(self):
        """Should detect English description."""
        data = [{"lang": "en", "value": "A vulnerability..."}]
        assert _custom_check(data, "english_description") is True
    
    def test_english_description_us_variant(self):
        """Should detect en-US as English."""
        data = [{"lang": "en-US", "value": "A vulnerability..."}]
        assert _custom_check(data, "english_description") is True
    
    def test_english_description_missing(self):
        """Should return False when no English description."""
        data = [{"lang": "es", "value": "Una vulnerabilidad..."}]
        assert _custom_check(data, "english_description") is False
    
    def test_multiple_languages_true(self):
        """Should detect multiple languages."""
        data = [
            {"lang": "en", "value": "English"},
            {"lang": "es", "value": "Spanish"}
        ]
        assert _custom_check(data, "multiple_languages") is True
    
    def test_multiple_languages_false(self):
        """Should return False for single language."""
        data = [{"lang": "en", "value": "English only"}]
        assert _custom_check(data, "multiple_languages") is False
    
    def test_supporting_media_present(self):
        """Should detect supporting media."""
        data = [{"lang": "en", "value": "text", "media": "image/png"}]
        assert _custom_check(data, "supporting_media") is True
    
    def test_supporting_media_missing(self):
        """Should return False when no media."""
        data = [{"lang": "en", "value": "text only"}]
        assert _custom_check(data, "supporting_media") is False


class TestCustomCheckAffected:
    """Tests for _custom_check with affected product checks."""
    
    def test_has_vendor(self):
        """Should detect vendor field."""
        data = [{"vendor": "Microsoft", "product": "Windows"}]
        assert _custom_check(data, "has_vendor") is True
    
    def test_has_vendor_missing(self):
        """Should return False when no vendor."""
        data = [{"product": "Unknown"}]
        assert _custom_check(data, "has_vendor") is False
    
    def test_has_product(self):
        """Should detect product field."""
        data = [{"product": "Firefox"}]
        assert _custom_check(data, "has_product") is True
    
    def test_has_versions(self):
        """Should detect versions field."""
        data = [{"product": "Chrome", "versions": [{"version": "1.0"}]}]
        assert _custom_check(data, "has_versions") is True
    
    def test_has_versions_empty(self):
        """Should return False for empty versions."""
        data = [{"product": "Chrome", "versions": []}]
        assert _custom_check(data, "has_versions") is False
    
    def test_has_default_status(self):
        """Should detect defaultStatus field."""
        data = [{"defaultStatus": "affected"}]
        assert _custom_check(data, "has_default_status") is True
    
    def test_has_cpes(self):
        """Should detect CPEs."""
        data = [{"cpes": ["cpe:2.3:a:vendor:product:*"]}]
        assert _custom_check(data, "has_cpes") is True
    
    def test_has_modules(self):
        """Should detect modules."""
        data = [{"modules": ["core", "auth"]}]
        assert _custom_check(data, "has_modules") is True
    
    def test_has_program_files(self):
        """Should detect programFiles."""
        data = [{"programFiles": ["/usr/bin/app"]}]
        assert _custom_check(data, "has_program_files") is True
    
    def test_has_program_routines(self):
        """Should detect programRoutines."""
        data = [{"programRoutines": [{"name": "main"}]}]
        assert _custom_check(data, "has_program_routines") is True
    
    def test_has_platforms(self):
        """Should detect platforms."""
        data = [{"platforms": ["Windows", "Linux"]}]
        assert _custom_check(data, "has_platforms") is True
    
    def test_has_repo(self):
        """Should detect repo."""
        data = [{"repo": "https://github.com/example/repo"}]
        assert _custom_check(data, "has_repo") is True


class TestCustomCheckProblemTypes:
    """Tests for _custom_check with problemTypes checks."""
    
    def test_has_cwe_explicit(self):
        """Should detect explicit CWE ID."""
        data = [{"descriptions": [{"cweId": "CWE-79", "description": "XSS"}]}]
        assert _custom_check(data, "has_cwe") is True
    
    def test_has_cwe_in_description(self):
        """Should detect CWE ID in description text."""
        data = [{"descriptions": [{"description": "CWE-79: Cross-site scripting"}]}]
        assert _custom_check(data, "has_cwe") is True
    
    def test_has_cwe_missing(self):
        """Should return False when no CWE."""
        data = [{"descriptions": [{"description": "Generic vulnerability"}]}]
        assert _custom_check(data, "has_cwe") is False
    
    def test_has_type(self):
        """Should detect type field."""
        data = [{"type": "primary"}]
        assert _custom_check(data, "has_type") is True
    
    def test_has_pt_references(self):
        """Should detect references in problemTypes."""
        data = [{"references": [{"url": "https://example.com"}]}]
        assert _custom_check(data, "has_pt_references") is True


class TestCustomCheckReferences:
    """Tests for _custom_check with reference checks."""
    
    def test_has_advisory_ref(self):
        """Should detect advisory reference."""
        data = [{"url": "https://example.com", "tags": ["vendor-advisory"]}]
        assert _custom_check(data, "has_advisory_ref") is True
    
    def test_has_patch_ref(self):
        """Should detect patch reference."""
        data = [{"url": "https://example.com", "tags": ["patch"]}]
        assert _custom_check(data, "has_patch_ref") is True
    
    def test_has_exploit_ref(self):
        """Should detect exploit reference."""
        data = [{"url": "https://example.com", "tags": ["exploit"]}]
        assert _custom_check(data, "has_exploit_ref") is True
    
    def test_has_technical_ref(self):
        """Should detect technical reference."""
        data = [{"url": "https://example.com", "tags": ["technical-description"]}]
        assert _custom_check(data, "has_technical_ref") is True
    
    def test_has_vendor_ref(self):
        """Should detect vendor reference."""
        data = [{"url": "https://example.com", "tags": ["vendor-advisory"]}]
        assert _custom_check(data, "has_vendor_ref") is True
    
    def test_has_named_ref(self):
        """Should detect named reference."""
        data = [{"url": "https://example.com", "name": "Security Advisory SA-2024-001"}]
        assert _custom_check(data, "has_named_ref") is True
    
    def test_reference_no_tags(self):
        """Should return False when no tags."""
        data = [{"url": "https://example.com"}]
        assert _custom_check(data, "has_patch_ref") is False


class TestCustomCheckMetrics:
    """Tests for _custom_check with metrics checks."""
    
    def test_has_cvss_v4(self):
        """Should detect CVSS v4.0."""
        data = [{"cvssV4_0": {"baseScore": 7.5}}]
        assert _custom_check(data, "has_cvss_v4") is True
    
    def test_has_cvss_v3_1(self):
        """Should detect CVSS v3.1."""
        data = [{"cvssV3_1": {"baseScore": 7.5}}]
        assert _custom_check(data, "has_cvss_v3_1") is True
    
    def test_has_cvss_v3_0(self):
        """Should detect CVSS v3.0."""
        data = [{"cvssV3_0": {"baseScore": 7.5}}]
        assert _custom_check(data, "has_cvss_v3_0") is True
    
    def test_has_cvss_v2(self):
        """Should detect CVSS v2.0."""
        data = [{"cvssV2_0": {"baseScore": 7.5}}]
        assert _custom_check(data, "has_cvss_v2") is True
    
    def test_has_other_metrics(self):
        """Should detect other metrics (SSVC, KEV, etc)."""
        data = [{"other": {"type": "ssvc", "content": {}}}]
        assert _custom_check(data, "has_other_metrics") is True
    
    def test_has_scenarios(self):
        """Should detect scenarios."""
        data = [{"scenarios": [{"lang": "en", "value": "default"}]}]
        assert _custom_check(data, "has_scenarios") is True


class TestCustomCheckEdgeCases:
    """Edge case tests for _custom_check."""
    
    def test_none_data(self):
        """Should handle None data."""
        assert _custom_check(None, "has_vendor") is False
    
    def test_empty_list(self):
        """Should handle empty list."""
        assert _custom_check([], "has_vendor") is False
    
    def test_non_list_data(self):
        """Should handle non-list data."""
        assert _custom_check("not a list", "has_vendor") is False
    
    def test_unknown_check_type(self):
        """Should return False for unknown check type."""
        assert _custom_check([{"data": "value"}], "unknown_check") is False
    
    def test_list_with_non_dict_items(self):
        """Should handle list with non-dict items."""
        data = [{"vendor": "Microsoft"}, "not a dict", None]
        assert _custom_check(data, "has_vendor") is True


class TestComputeFieldUtilization:
    """Tests for compute_field_utilization function."""
    
    @pytest.fixture
    def sample_cve_records(self):
        """Sample CVE records for testing."""
        return [
            {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.1",
                "cveMetadata": {
                    "cveId": "CVE-2024-0001",
                    "assignerOrgId": "org-1"
                },
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "affected": [{"vendor": "Vendor1", "product": "Product1"}],
                        "references": [{"url": "https://example.com", "tags": ["patch"]}]
                    }
                }
            },
            {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.1",
                "cveMetadata": {
                    "cveId": "CVE-2024-0002",
                    "assignerOrgId": "org-2"
                },
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "Test 2"}],
                        "affected": [{"vendor": "Vendor2"}]
                    }
                }
            }
        ]
    
    def test_basic_utilization(self, sample_cve_records):
        """Should compute basic field utilization."""
        field_list = ["dataType", "containers.cna.descriptions"]
        result = compute_field_utilization(sample_cve_records, field_list)
        
        assert len(result) == 2
        assert any(f["field"] == "dataType" for f in result)
        assert any(f["field"] == "containers.cna.descriptions" for f in result)
    
    def test_utilization_percentages(self, sample_cve_records):
        """Should calculate correct percentages."""
        field_list = ["dataType"]
        result = compute_field_utilization(sample_cve_records, field_list)
        
        data_type_result = next(f for f in result if f["field"] == "dataType")
        assert data_type_result["cna_percent"] == 100.0
        assert data_type_result["unique_cnas"] == 2
    
    def test_partial_utilization(self, sample_cve_records):
        """Should handle fields not present in all records."""
        field_list = ["references.patch"]
        result = compute_field_utilization(sample_cve_records, field_list)
        
        patch_result = next(f for f in result if f["field"] == "references.patch")
        # Only org-1 has patch references
        assert patch_result["cna_percent"] == 50.0
        assert patch_result["unique_cnas"] == 1
    
    def test_empty_records(self):
        """Should handle empty record list."""
        result = compute_field_utilization([], ["dataType"])
        assert len(result) == 1
        assert result[0]["cna_percent"] == 0
        assert result[0]["unique_cnas"] == 0
    
    def test_unknown_field(self, sample_cve_records):
        """Should handle unknown fields gracefully."""
        field_list = ["unknown.field", "dataType"]
        result = compute_field_utilization(sample_cve_records, field_list)
        # Should still return results, unknown field just won't match
        assert len(result) == 2
    
    def test_sorted_by_percent(self, sample_cve_records):
        """Results should be sorted by percent descending."""
        field_list = ["dataType", "references.patch"]
        result = compute_field_utilization(sample_cve_records, field_list)
        
        # dataType (100%) should come before references.patch (50%)
        assert result[0]["cna_percent"] >= result[1]["cna_percent"]


class TestComputeIndividualCNAFieldUtilization:
    """Tests for compute_individual_cna_field_utilization function."""
    
    @pytest.fixture
    def sample_cve_records_with_shortname(self):
        """Sample CVE records with providerMetadata shortName."""
        return [
            {
                "cveMetadata": {"cveId": "CVE-2024-0001"},
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "TestCNA"},
                        "descriptions": [{"lang": "en", "value": "Test"}],
                        "affected": [{"vendor": "V1", "product": "P1"}]
                    }
                }
            },
            {
                "cveMetadata": {"cveId": "CVE-2024-0002"},
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "TestCNA"},
                        "descriptions": [{"lang": "en", "value": "Test 2"}]
                    }
                }
            },
            {
                "cveMetadata": {"cveId": "CVE-2024-0003"},
                "containers": {
                    "cna": {
                        "providerMetadata": {"shortName": "OtherCNA"},
                        "descriptions": [{"lang": "en", "value": "Other"}],
                        "affected": [{"vendor": "V2"}]
                    }
                }
            }
        ]
    
    def test_basic_individual_utilization(self, sample_cve_records_with_shortname):
        """Should compute utilization per CNA."""
        field_list = ["descriptions.english", "affected.vendor"]
        result = compute_individual_cna_field_utilization(
            sample_cve_records_with_shortname, field_list
        )
        
        assert "TestCNA" in result
        assert "OtherCNA" in result
    
    def test_utilization_per_cna(self, sample_cve_records_with_shortname):
        """Should track field usage per CNA correctly."""
        field_list = ["affected.vendor"]
        result = compute_individual_cna_field_utilization(
            sample_cve_records_with_shortname, field_list
        )
        
        # TestCNA: 1/2 CVEs have affected.vendor = 50%
        test_cna = result["TestCNA"]
        vendor_field = next(f for f in test_cna if f["field"] == "affected.vendor")
        assert vendor_field["percent"] == 50.0
        assert vendor_field["cve_count"] == 1
        assert vendor_field["total_cves"] == 2
        
        # OtherCNA: 1/1 CVEs have affected.vendor = 100%
        other_cna = result["OtherCNA"]
        vendor_field = next(f for f in other_cna if f["field"] == "affected.vendor")
        assert vendor_field["percent"] == 100.0
        assert vendor_field["cve_count"] == 1
        assert vendor_field["total_cves"] == 1
    
    def test_empty_records(self):
        """Should handle empty record list."""
        result = compute_individual_cna_field_utilization([], ["dataType"])
        assert result == {}
    
    def test_records_without_shortname(self):
        """Should skip records without shortName."""
        records = [
            {
                "cveMetadata": {"cveId": "CVE-2024-0001"},
                "containers": {
                    "cna": {
                        "descriptions": [{"lang": "en", "value": "No shortName"}]
                    }
                }
            }
        ]
        result = compute_individual_cna_field_utilization(records, ["dataType"])
        assert result == {}
