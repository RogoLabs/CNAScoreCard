"""
Tests for chunking.py - Data chunking for web lazy loading.
"""
import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from chunking import (
    write_chunked_cna_data,
    write_chunked_completeness_data,
    generate_search_index,
    generate_summary_stats,
    cleanup_old_chunks,
    _get_timestamp,
    _grade_sort_key
)


class TestWriteChunkedCNAData:
    """Tests for write_chunked_cna_data function."""
    
    @pytest.fixture
    def sample_cna_list(self):
        """Sample CNA data for testing."""
        return [
            {"shortName": f"CNA_{i}", "cnaId": f"id_{i}", "grade": "A" if i % 2 == 0 else "B"}
            for i in range(125)
        ]
    
    def test_creates_chunks(self, sample_cna_list, tmp_path):
        """Should create chunk files."""
        manifest = write_chunked_cna_data(sample_cna_list, tmp_path, chunk_size=50)
        
        chunks_dir = tmp_path / "chunks"
        assert chunks_dir.exists()
        assert (chunks_dir / "manifest.json").exists()
        
        # 125 items / 50 per chunk = 3 chunks
        assert manifest["totalChunks"] == 3
        assert manifest["totalCNAs"] == 125
        assert manifest["chunkSize"] == 50
    
    def test_chunk_file_contents(self, sample_cna_list, tmp_path):
        """Chunk files should contain correct data."""
        write_chunked_cna_data(sample_cna_list, tmp_path, chunk_size=50)
        
        # Check first chunk
        chunk_0_path = tmp_path / "chunks" / "cna_chunk_0.json"
        with open(chunk_0_path) as f:
            chunk_0 = json.load(f)
        
        assert chunk_0["chunkIndex"] == 0
        assert chunk_0["startIndex"] == 0
        assert chunk_0["endIndex"] == 50
        assert chunk_0["count"] == 50
        assert len(chunk_0["items"]) == 50
    
    def test_last_chunk_partial(self, sample_cna_list, tmp_path):
        """Last chunk should have remaining items."""
        write_chunked_cna_data(sample_cna_list, tmp_path, chunk_size=50)
        
        # Last chunk has 125 - 100 = 25 items
        chunk_2_path = tmp_path / "chunks" / "cna_chunk_2.json"
        with open(chunk_2_path) as f:
            chunk_2 = json.load(f)
        
        assert chunk_2["count"] == 25
        assert len(chunk_2["items"]) == 25
    
    def test_manifest_lists_all_chunks(self, sample_cna_list, tmp_path):
        """Manifest should list all chunk files."""
        manifest = write_chunked_cna_data(sample_cna_list, tmp_path, chunk_size=50)
        
        assert len(manifest["chunks"]) == 3
        assert "cna_chunk_0.json" in manifest["chunks"]
        assert "cna_chunk_1.json" in manifest["chunks"]
        assert "cna_chunk_2.json" in manifest["chunks"]
    
    def test_empty_list(self, tmp_path):
        """Should handle empty CNA list."""
        manifest = write_chunked_cna_data([], tmp_path, chunk_size=50)
        
        assert manifest["totalCNAs"] == 0
        assert manifest["totalChunks"] == 0
        assert manifest["chunks"] == []
    
    def test_small_list_single_chunk(self, tmp_path):
        """List smaller than chunk_size should create one chunk."""
        small_list = [{"shortName": f"CNA_{i}"} for i in range(10)]
        manifest = write_chunked_cna_data(small_list, tmp_path, chunk_size=50)
        
        assert manifest["totalChunks"] == 1
        assert manifest["totalCNAs"] == 10
    
    def test_custom_chunk_size(self, sample_cna_list, tmp_path):
        """Should respect custom chunk size."""
        manifest = write_chunked_cna_data(sample_cna_list, tmp_path, chunk_size=25)
        
        # 125 / 25 = 5 chunks
        assert manifest["totalChunks"] == 5
        assert manifest["chunkSize"] == 25


class TestWriteChunkedCompletenessData:
    """Tests for write_chunked_completeness_data function."""
    
    @pytest.fixture
    def sample_completeness_list(self):
        """Sample completeness data for testing."""
        return [
            {"cnaName": f"CNA_{i}", "completeness": 75.0 + i}
            for i in range(150)
        ]
    
    def test_creates_completeness_chunks(self, sample_completeness_list, tmp_path):
        """Should create completeness chunk files."""
        manifest = write_chunked_completeness_data(sample_completeness_list, tmp_path, chunk_size=100)
        
        chunks_dir = tmp_path / "completeness" / "chunks"
        assert chunks_dir.exists()
        assert (chunks_dir / "manifest.json").exists()
        
        # 150 / 100 = 2 chunks
        assert manifest["totalChunks"] == 2
        assert manifest["totalItems"] == 150
    
    def test_completeness_chunk_files_created(self, sample_completeness_list, tmp_path):
        """Should create properly named chunk files."""
        write_chunked_completeness_data(sample_completeness_list, tmp_path, chunk_size=100)
        
        chunks_dir = tmp_path / "completeness" / "chunks"
        assert (chunks_dir / "completeness_chunk_0.json").exists()
        assert (chunks_dir / "completeness_chunk_1.json").exists()


class TestGenerateSearchIndex:
    """Tests for generate_search_index function."""
    
    @pytest.fixture
    def sample_cna_list(self):
        """Sample CNA data for search index."""
        return [
            {"shortName": "Microsoft", "cnaId": "msft-001", "type": "Vendor", "grade": "A", "country": "US"},
            {"shortName": "Google", "cnaId": "goog-001", "type": "Vendor", "grade": "B", "country": "US"},
            {"shortName": "RedHat", "cnaId": "rh-001", "type": "Vendor", "grade": "A", "country": "US"},
            {"shortName": "CERT/CC", "cnaId": "cert-001", "type": "Coordinator", "grade": "A", "country": "US"}
        ]
    
    def test_creates_search_index(self, sample_cna_list, tmp_path):
        """Should create search index file."""
        search_index = generate_search_index(sample_cna_list, tmp_path)
        
        assert (tmp_path / "search_index.json").exists()
        assert search_index["totalCNAs"] == 4
    
    def test_extracts_cna_names(self, sample_cna_list, tmp_path):
        """Should extract CNA names."""
        search_index = generate_search_index(sample_cna_list, tmp_path)
        
        assert "Microsoft" in search_index["cnaNames"]
        assert "Google" in search_index["cnaNames"]
        assert len(search_index["cnaNames"]) == 4
    
    def test_extracts_cna_ids(self, sample_cna_list, tmp_path):
        """Should extract CNA IDs."""
        search_index = generate_search_index(sample_cna_list, tmp_path)
        
        assert "msft-001" in search_index["cnaIds"]
        assert len(search_index["cnaIds"]) == 4
    
    def test_extracts_unique_types(self, sample_cna_list, tmp_path):
        """Should extract unique CNA types."""
        search_index = generate_search_index(sample_cna_list, tmp_path)
        
        assert "Vendor" in search_index["types"]
        assert "Coordinator" in search_index["types"]
        assert len(search_index["types"]) == 2
    
    def test_extracts_unique_grades(self, sample_cna_list, tmp_path):
        """Should extract unique grades sorted properly."""
        search_index = generate_search_index(sample_cna_list, tmp_path)
        
        assert "A" in search_index["grades"]
        assert "B" in search_index["grades"]
        # Grades should be sorted A, B
        assert search_index["grades"] == ["A", "B"]
    
    def test_extracts_unique_countries(self, sample_cna_list, tmp_path):
        """Should extract unique countries."""
        search_index = generate_search_index(sample_cna_list, tmp_path)
        
        assert "US" in search_index["countries"]
    
    def test_handles_missing_fields(self, tmp_path):
        """Should handle CNAs with missing fields."""
        cna_list = [
            {"shortName": "CNA1"},  # Missing most fields
            {"cnaId": "id-only"}    # Missing shortName
        ]
        search_index = generate_search_index(cna_list, tmp_path)
        
        assert "CNA1" in search_index["cnaNames"]
        assert "id-only" in search_index["cnaIds"]
        assert search_index["totalCNAs"] == 2


class TestGenerateSummaryStats:
    """Tests for generate_summary_stats function."""
    
    @pytest.fixture
    def sample_cna_list(self):
        """Sample CNA data for summary stats."""
        return [
            {"shortName": "CNA1", "cveCount": 100, "overallScore": 85, "grade": "A", "type": "Vendor", "trend": "up"},
            {"shortName": "CNA2", "cveCount": 50, "overallScore": 75, "grade": "B", "type": "Vendor", "trend": "steady"},
            {"shortName": "CNA3", "cveCount": 25, "overallScore": 60, "grade": "C", "type": "Coordinator", "trend": "down"}
        ]
    
    def test_creates_summary_stats(self, sample_cna_list, tmp_path):
        """Should create summary stats file."""
        stats = generate_summary_stats(sample_cna_list, tmp_path)
        
        assert (tmp_path / "summary_stats.json").exists()
    
    def test_total_cnas(self, sample_cna_list, tmp_path):
        """Should count total CNAs."""
        stats = generate_summary_stats(sample_cna_list, tmp_path)
        assert stats["totalCNAs"] == 3
    
    def test_total_cves(self, sample_cna_list, tmp_path):
        """Should sum total CVEs."""
        stats = generate_summary_stats(sample_cna_list, tmp_path)
        assert stats["totalCVEs"] == 175  # 100 + 50 + 25
    
    def test_average_score(self, sample_cna_list, tmp_path):
        """Should calculate average score."""
        stats = generate_summary_stats(sample_cna_list, tmp_path)
        # (85 + 75 + 60) / 3 = 73.33...
        assert stats["averageScore"] == 73.3
    
    def test_grade_distribution(self, sample_cna_list, tmp_path):
        """Should count grades."""
        stats = generate_summary_stats(sample_cna_list, tmp_path)
        
        assert stats["gradeDistribution"]["A"] == 1
        assert stats["gradeDistribution"]["B"] == 1
        assert stats["gradeDistribution"]["C"] == 1
        assert stats["gradeDistribution"]["D"] == 0
        assert stats["gradeDistribution"]["F"] == 0
    
    def test_type_distribution(self, sample_cna_list, tmp_path):
        """Should count types."""
        stats = generate_summary_stats(sample_cna_list, tmp_path)
        
        assert stats["typeDistribution"]["Vendor"] == 2
        assert stats["typeDistribution"]["Coordinator"] == 1
    
    def test_trend_distribution(self, sample_cna_list, tmp_path):
        """Should count trends."""
        stats = generate_summary_stats(sample_cna_list, tmp_path)
        
        assert stats["trendDistribution"]["up"] == 1
        assert stats["trendDistribution"]["steady"] == 1
        assert stats["trendDistribution"]["down"] == 1


class TestCleanupOldChunks:
    """Tests for cleanup_old_chunks function."""
    
    def test_removes_chunk_files(self, tmp_path):
        """Should remove chunk files."""
        chunks_dir = tmp_path / "chunks"
        chunks_dir.mkdir()
        
        # Create some chunk files
        (chunks_dir / "cna_chunk_0.json").write_text("{}")
        (chunks_dir / "cna_chunk_1.json").write_text("{}")
        (chunks_dir / "completeness_chunk_0.json").write_text("{}")
        
        removed = cleanup_old_chunks(chunks_dir)
        
        assert removed == 3
        assert not (chunks_dir / "cna_chunk_0.json").exists()
    
    def test_nonexistent_directory(self, tmp_path):
        """Should handle non-existent directory."""
        removed = cleanup_old_chunks(tmp_path / "nonexistent")
        assert removed == 0
    
    def test_empty_directory(self, tmp_path):
        """Should handle empty directory."""
        chunks_dir = tmp_path / "chunks"
        chunks_dir.mkdir()
        
        removed = cleanup_old_chunks(chunks_dir)
        assert removed == 0


class TestHelperFunctions:
    """Tests for helper functions."""
    
    def test_get_timestamp_format(self):
        """Should return ISO format timestamp."""
        timestamp = _get_timestamp()
        
        # Should match format like 2024-01-15T10:30:00Z
        assert "T" in timestamp
        assert timestamp.endswith("Z")
        assert len(timestamp) == 20
    
    def test_grade_sort_key_order(self):
        """Should return correct sort order for grades."""
        assert _grade_sort_key("A") == 0
        assert _grade_sort_key("B") == 1
        assert _grade_sort_key("C") == 2
        assert _grade_sort_key("D") == 3
        assert _grade_sort_key("F") == 4
    
    def test_grade_sort_key_unknown(self):
        """Should handle unknown grades."""
        assert _grade_sort_key("X") == 5
        assert _grade_sort_key("") == 5
