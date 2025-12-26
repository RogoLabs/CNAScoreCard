"""
cache.py: Caching layer for computed CVE scores.

This module provides caching functionality to avoid recomputing scores
for CVEs that haven't changed, significantly improving pipeline performance
for incremental runs.
"""
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from config import WEB_DATA_DIR

logger = logging.getLogger('cnascorecard.cache')

# Default cache directory
CACHE_DIR = WEB_DATA_DIR / ".cache" / "scores"


class ScoreCache:
    """
    Cache for computed CVE scores.
    
    The cache stores scores indexed by CVE ID and a hash of the CVE content.
    When a CVE's content changes, its hash changes, invalidating the cache.
    
    Example:
        >>> cache = ScoreCache()
        >>> 
        >>> # Check if score is cached
        >>> cached_score = cache.get(cve_id, cve_data)
        >>> if cached_score:
        ...     score = cached_score
        ... else:
        ...     score = compute_score(cve_data)
        ...     cache.set(cve_id, cve_data, score)
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize the score cache.
        
        Args:
            cache_dir: Directory to store cache files (defaults to CACHE_DIR)
        """
        self.cache_dir = Path(cache_dir) if cache_dir else CACHE_DIR
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
        self._hits = 0
        self._misses = 0
        self._initialized = False
    
    def _ensure_initialized(self) -> None:
        """Ensure cache directory exists."""
        if not self._initialized:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._initialized = True
    
    @staticmethod
    def compute_hash(cve_data: Dict[str, Any]) -> str:
        """
        Compute a hash of CVE data for cache validation.
        
        The hash is computed from the JSON-serialized CVE data, ensuring
        that any change to the CVE invalidates the cache.
        
        Args:
            cve_data: CVE record dictionary
            
        Returns:
            SHA256 hash of the CVE data (first 16 chars)
        """
        # Sort keys for consistent ordering
        json_str = json.dumps(cve_data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(json_str.encode()).hexdigest()[:16]
    
    def get(self, cve_id: str, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Retrieve a cached score if the CVE hasn't changed.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2025-10150")
            cve_data: Current CVE record data
            
        Returns:
            Cached score dictionary if valid, None if cache miss
        """
        current_hash = self.compute_hash(cve_data)
        
        # Check memory cache first
        if cve_id in self._memory_cache:
            cached = self._memory_cache[cve_id]
            if cached.get("hash") == current_hash:
                self._hits += 1
                return cached.get("score")
        
        # Check disk cache
        cache_file = self._get_cache_path(cve_id)
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    cached = json.load(f)
                
                if cached.get("hash") == current_hash:
                    # Load into memory cache for faster subsequent access
                    self._memory_cache[cve_id] = cached
                    self._hits += 1
                    return cached.get("score")
            except (json.JSONDecodeError, IOError) as e:
                logger.debug(f"Error reading cache for {cve_id}: {e}")
        
        self._misses += 1
        return None
    
    def set(self, cve_id: str, cve_data: Dict[str, Any], score: Dict[str, Any]) -> None:
        """
        Store a computed score in the cache.
        
        Args:
            cve_id: CVE identifier
            cve_data: CVE record data (used to compute hash)
            score: Computed score to cache
        """
        self._ensure_initialized()
        
        cached = {
            "cve_id": cve_id,
            "hash": self.compute_hash(cve_data),
            "score": score,
            "cached_at": datetime.utcnow().isoformat()
        }
        
        # Update memory cache
        self._memory_cache[cve_id] = cached
        
        # Write to disk
        cache_file = self._get_cache_path(cve_id)
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(cache_file, 'w') as f:
                json.dump(cached, f)
        except IOError as e:
            logger.warning(f"Error writing cache for {cve_id}: {e}")
    
    def get_batch(
        self, 
        cve_records: List[Dict[str, Any]]
    ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Get cached scores for a batch of CVEs, returning hits and misses.
        
        This is more efficient than individual get() calls when processing
        many CVEs.
        
        Args:
            cve_records: List of CVE record dictionaries
            
        Returns:
            Tuple of:
            - Dict mapping CVE IDs to cached scores
            - List of CVE records that need scoring (cache misses)
        """
        cached_scores = {}
        uncached_cves = []
        
        for cve in cve_records:
            cve_id = cve.get("cveMetadata", {}).get("cveId")
            if not cve_id:
                uncached_cves.append(cve)
                continue
            
            cached = self.get(cve_id, cve)
            if cached:
                cached_scores[cve_id] = cached
            else:
                uncached_cves.append(cve)
        
        logger.info(f"Cache batch: {len(cached_scores)} hits, {len(uncached_cves)} misses")
        return cached_scores, uncached_cves
    
    def set_batch(
        self, 
        scores: List[Dict[str, Any]], 
        cve_lookup: Dict[str, Dict[str, Any]]
    ) -> None:
        """
        Store multiple scores in the cache.
        
        Args:
            scores: List of score dictionaries (must contain 'cveId')
            cve_lookup: Dict mapping CVE IDs to their record data
        """
        for score in scores:
            cve_id = score.get("cveId")
            if cve_id and cve_id in cve_lookup:
                self.set(cve_id, cve_lookup[cve_id], score)
    
    def _get_cache_path(self, cve_id: str) -> Path:
        """
        Get the cache file path for a CVE ID.
        
        Cache files are organized by year to avoid too many files in one directory.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Path to cache file
        """
        # Extract year from CVE ID (CVE-YYYY-NNNNN)
        parts = cve_id.split("-")
        year = parts[1] if len(parts) >= 2 else "unknown"
        
        return self.cache_dir / year / f"{cve_id}.json"
    
    def clear(self, older_than_days: Optional[int] = None) -> int:
        """
        Clear cached scores.
        
        Args:
            older_than_days: If provided, only clear entries older than this many days.
                            If None, clears all entries.
                            
        Returns:
            Number of cache entries cleared
        """
        self._memory_cache.clear()
        cleared = 0
        
        if not self.cache_dir.exists():
            return 0
        
        cutoff = None
        if older_than_days:
            from datetime import timedelta
            cutoff = datetime.utcnow() - timedelta(days=older_than_days)
        
        for cache_file in self.cache_dir.rglob("CVE-*.json"):
            try:
                if cutoff:
                    with open(cache_file, 'r') as f:
                        cached = json.load(f)
                    cached_at = datetime.fromisoformat(cached.get("cached_at", ""))
                    if cached_at > cutoff:
                        continue
                
                cache_file.unlink()
                cleared += 1
            except Exception as e:
                logger.debug(f"Error clearing cache file {cache_file}: {e}")
        
        logger.info(f"Cleared {cleared} cache entries")
        return cleared
    
    def stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.
        
        Returns:
            Dict with hits, misses, hit_rate, and memory_entries
        """
        total = self._hits + self._misses
        hit_rate = (self._hits / total * 100) if total > 0 else 0
        
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.1f}%",
            "memory_entries": len(self._memory_cache)
        }
    
    def __repr__(self) -> str:
        stats = self.stats()
        return f"ScoreCache(hits={stats['hits']}, misses={stats['misses']}, rate={stats['hit_rate']})"


# Global cache instance
_global_cache: Optional[ScoreCache] = None


def get_cache(cache_dir: Optional[Path] = None) -> ScoreCache:
    """
    Get the global score cache instance.
    
    Args:
        cache_dir: Optional cache directory (only used on first call)
        
    Returns:
        ScoreCache instance
    """
    global _global_cache
    if _global_cache is None:
        _global_cache = ScoreCache(cache_dir)
    return _global_cache


def reset_cache() -> None:
    """Reset the global cache instance."""
    global _global_cache
    _global_cache = None


def score_with_cache(
    cve_records: List[Dict[str, Any]],
    scoring_func,
    cache: Optional[ScoreCache] = None
) -> List[Dict[str, Any]]:
    """
    Score CVE records using cache for efficiency.
    
    This is a convenience function that wraps the caching logic around
    any scoring function.
    
    Args:
        cve_records: List of CVE record dictionaries
        scoring_func: Function that takes a CVE record and returns a score dict
        cache: ScoreCache instance (uses global cache if not provided)
        
    Returns:
        List of score dictionaries
    """
    if cache is None:
        cache = get_cache()
    
    # Check cache for existing scores
    cached_scores, uncached_cves = cache.get_batch(cve_records)
    
    # Score uncached CVEs
    new_scores = []
    cve_lookup = {}
    
    for cve in uncached_cves:
        cve_id = cve.get("cveMetadata", {}).get("cveId")
        if cve_id:
            cve_lookup[cve_id] = cve
        
        try:
            score = scoring_func(cve)
            if score:
                new_scores.append(score)
        except Exception as e:
            logger.debug(f"Error scoring CVE: {e}")
    
    # Cache the new scores
    cache.set_batch(new_scores, cve_lookup)
    
    # Combine cached and new scores
    all_scores = list(cached_scores.values()) + new_scores
    
    logger.info(f"Scoring complete: {len(cached_scores)} cached, {len(new_scores)} computed")
    return all_scores
