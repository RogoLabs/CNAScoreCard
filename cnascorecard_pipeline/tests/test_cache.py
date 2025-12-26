"""
Tests for cache.py - Score caching for CVE data.
"""
import json
import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from cache import ScoreCache, get_cache, reset_cache


class TestScoreCacheInit:
    """Tests for ScoreCache initialization."""
    
    def test_default_cache_dir(self, tmp_path, monkeypatch):
        """Should use default cache directory."""
        cache = ScoreCache(cache_dir=tmp_path)
        assert cache.cache_dir == tmp_path
    
    def test_custom_cache_dir(self, tmp_path):
        """Should accept custom cache directory."""
        custom_dir = tmp_path / "custom_cache"
        cache = ScoreCache(cache_dir=custom_dir)
        assert cache.cache_dir == custom_dir
    
    def test_creates_directory_on_first_write(self, tmp_path):
        """Should create cache directory when needed."""
        cache_dir = tmp_path / "new_cache"
        cache = ScoreCache(cache_dir=cache_dir)
        
        # Directory shouldn't exist yet
        assert not cache_dir.exists()
        
        # Trigger initialization
        cache.set("CVE-2024-0001", {"data": "test"}, {"score": 50})
        
        # Now it should exist
        assert cache_dir.exists()


class TestComputeHash:
    """Tests for ScoreCache.compute_hash static method."""
    
    def test_consistent_hash(self):
        """Same data should produce same hash."""
        data = {"key": "value", "nested": {"a": 1}}
        hash1 = ScoreCache.compute_hash(data)
        hash2 = ScoreCache.compute_hash(data)
        assert hash1 == hash2
    
    def test_different_data_different_hash(self):
        """Different data should produce different hash."""
        data1 = {"key": "value1"}
        data2 = {"key": "value2"}
        assert ScoreCache.compute_hash(data1) != ScoreCache.compute_hash(data2)
    
    def test_order_independent(self):
        """Key order shouldn't affect hash."""
        data1 = {"a": 1, "b": 2}
        data2 = {"b": 2, "a": 1}
        assert ScoreCache.compute_hash(data1) == ScoreCache.compute_hash(data2)
    
    def test_hash_length(self):
        """Hash should be 16 characters."""
        data = {"test": "data"}
        hash_val = ScoreCache.compute_hash(data)
        assert len(hash_val) == 16
    
    def test_hash_is_hex(self):
        """Hash should be hexadecimal."""
        data = {"test": "data"}
        hash_val = ScoreCache.compute_hash(data)
        int(hash_val, 16)  # Should not raise


class TestScoreCacheGetSet:
    """Tests for ScoreCache get and set methods."""
    
    @pytest.fixture
    def cache(self, tmp_path):
        """Create a cache instance for testing."""
        return ScoreCache(cache_dir=tmp_path)
    
    @pytest.fixture
    def sample_cve_data(self):
        """Sample CVE data for testing."""
        return {
            "cveMetadata": {"cveId": "CVE-2024-0001"},
            "containers": {"cna": {"descriptions": [{"value": "test"}]}}
        }
    
    @pytest.fixture
    def sample_score(self):
        """Sample score data for testing."""
        return {
            "cveId": "CVE-2024-0001",
            "totalScore": 75,
            "scoreBreakdown": {"foundational": 40, "rootCause": 10}
        }
    
    def test_set_and_get(self, cache, sample_cve_data, sample_score):
        """Should store and retrieve scores."""
        cve_id = "CVE-2024-0001"
        cache.set(cve_id, sample_cve_data, sample_score)
        
        retrieved = cache.get(cve_id, sample_cve_data)
        assert retrieved == sample_score
    
    def test_get_miss(self, cache, sample_cve_data):
        """Should return None for cache miss."""
        result = cache.get("CVE-2024-9999", sample_cve_data)
        assert result is None
    
    def test_get_stale_cache(self, cache, sample_cve_data, sample_score):
        """Should return None if CVE data changed."""
        cve_id = "CVE-2024-0001"
        cache.set(cve_id, sample_cve_data, sample_score)
        
        # Modify the CVE data
        modified_data = sample_cve_data.copy()
        modified_data["containers"] = {"cna": {"descriptions": [{"value": "modified"}]}}
        
        # Should return None because hash doesn't match
        result = cache.get(cve_id, modified_data)
        assert result is None
    
    def test_cache_persists_to_disk(self, tmp_path, sample_cve_data, sample_score):
        """Cache should persist to disk."""
        cve_id = "CVE-2024-0001"
        
        # Create cache and set value
        cache1 = ScoreCache(cache_dir=tmp_path)
        cache1.set(cve_id, sample_cve_data, sample_score)
        
        # Create new cache instance (simulating restart)
        cache2 = ScoreCache(cache_dir=tmp_path)
        
        # Should still retrieve from disk
        retrieved = cache2.get(cve_id, sample_cve_data)
        assert retrieved == sample_score


class TestScoreCacheBatch:
    """Tests for batch cache operations."""
    
    @pytest.fixture
    def cache(self, tmp_path):
        """Create a cache instance for testing."""
        return ScoreCache(cache_dir=tmp_path)
    
    @pytest.fixture
    def sample_cve_records(self):
        """Sample CVE records for batch testing."""
        return [
            {"cveMetadata": {"cveId": "CVE-2024-0001"}, "data": "cve1"},
            {"cveMetadata": {"cveId": "CVE-2024-0002"}, "data": "cve2"},
            {"cveMetadata": {"cveId": "CVE-2024-0003"}, "data": "cve3"}
        ]
    
    def test_get_batch_all_misses(self, cache, sample_cve_records):
        """Should return all as misses when cache is empty."""
        cached, uncached = cache.get_batch(sample_cve_records)
        
        assert len(cached) == 0
        assert len(uncached) == 3
    
    def test_get_batch_partial_hits(self, cache, sample_cve_records):
        """Should return mix of hits and misses."""
        # Cache first CVE
        cache.set("CVE-2024-0001", sample_cve_records[0], {"score": 50})
        
        cached, uncached = cache.get_batch(sample_cve_records)
        
        assert len(cached) == 1
        assert "CVE-2024-0001" in cached
        assert len(uncached) == 2
    
    def test_get_batch_handles_missing_cve_id(self, cache):
        """Should handle records without CVE ID."""
        records = [
            {"data": "no_cve_id"},
            {"cveMetadata": {"cveId": "CVE-2024-0001"}, "data": "has_id"}
        ]
        
        cached, uncached = cache.get_batch(records)
        
        assert len(uncached) == 2  # Both should be uncached
    
    def test_set_batch(self, cache, sample_cve_records):
        """Should cache multiple scores."""
        scores = [
            {"cveId": "CVE-2024-0001", "score": 50},
            {"cveId": "CVE-2024-0002", "score": 60}
        ]
        cve_lookup = {
            "CVE-2024-0001": sample_cve_records[0],
            "CVE-2024-0002": sample_cve_records[1]
        }
        
        cache.set_batch(scores, cve_lookup)
        
        # Verify both were cached
        assert cache.get("CVE-2024-0001", sample_cve_records[0]) == scores[0]
        assert cache.get("CVE-2024-0002", sample_cve_records[1]) == scores[1]


class TestScoreCacheClear:
    """Tests for cache clearing."""
    
    @pytest.fixture
    def cache(self, tmp_path):
        """Create a cache instance for testing."""
        return ScoreCache(cache_dir=tmp_path)
    
    def test_clear_all(self, cache):
        """Should clear all cache entries."""
        # Add some entries
        cache.set("CVE-2024-0001", {"data": "1"}, {"score": 50})
        cache.set("CVE-2024-0002", {"data": "2"}, {"score": 60})
        
        cleared = cache.clear()
        
        assert cleared == 2
        assert cache.get("CVE-2024-0001", {"data": "1"}) is None
        assert cache.get("CVE-2024-0002", {"data": "2"}) is None
    
    def test_clear_empty_cache(self, cache):
        """Should handle clearing empty cache."""
        cleared = cache.clear()
        assert cleared == 0


class TestScoreCacheStats:
    """Tests for cache statistics."""
    
    @pytest.fixture
    def cache(self, tmp_path):
        """Create a cache instance for testing."""
        return ScoreCache(cache_dir=tmp_path)
    
    def test_initial_stats(self, cache):
        """Should start with zero stats."""
        stats = cache.stats()
        
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["hit_rate"] == "0.0%"
        assert stats["memory_entries"] == 0
    
    def test_stats_after_operations(self, cache):
        """Should track hits and misses."""
        cve_data = {"data": "test"}
        
        # Miss (first access)
        cache.get("CVE-2024-0001", cve_data)
        
        # Set the value
        cache.set("CVE-2024-0001", cve_data, {"score": 50})
        
        # Hit (cached access)
        cache.get("CVE-2024-0001", cve_data)
        
        stats = cache.stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == "50.0%"
        assert stats["memory_entries"] == 1
    
    def test_repr(self, cache):
        """Should have useful repr."""
        repr_str = repr(cache)
        assert "ScoreCache" in repr_str
        assert "hits=" in repr_str
        assert "misses=" in repr_str


class TestScoreCachePath:
    """Tests for cache path organization."""
    
    @pytest.fixture
    def cache(self, tmp_path):
        """Create a cache instance for testing."""
        return ScoreCache(cache_dir=tmp_path)
    
    def test_organizes_by_year(self, cache, tmp_path):
        """Should organize cache files by year."""
        cache.set("CVE-2024-0001", {"data": "1"}, {"score": 50})
        cache.set("CVE-2023-0001", {"data": "2"}, {"score": 60})
        
        # Check directory structure
        assert (tmp_path / "2024" / "CVE-2024-0001.json").exists()
        assert (tmp_path / "2023" / "CVE-2023-0001.json").exists()


class TestGlobalCache:
    """Tests for global cache functions."""
    
    def test_get_cache_returns_instance(self, tmp_path, monkeypatch):
        """get_cache should return a ScoreCache instance."""
        # Clear any existing global cache
        reset_cache()
        
        cache = get_cache(cache_dir=tmp_path)
        assert isinstance(cache, ScoreCache)
    
    def test_get_cache_returns_same_instance(self, tmp_path):
        """get_cache should return same instance on subsequent calls."""
        reset_cache()
        
        cache1 = get_cache(cache_dir=tmp_path)
        cache2 = get_cache(cache_dir=tmp_path)
        
        assert cache1 is cache2
    
    def test_reset_cache(self, tmp_path):
        """reset_cache should reset the global instance."""
        reset_cache()
        cache1 = get_cache(cache_dir=tmp_path)
        
        reset_cache()
        cache2 = get_cache(cache_dir=tmp_path)
        
        # Should be different instances after reset
        assert cache1 is not cache2
