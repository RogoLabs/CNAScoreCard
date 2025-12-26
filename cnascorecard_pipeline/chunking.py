"""
chunking.py: Data chunking for web lazy loading.

This module provides functionality to split large JSON data files into
smaller chunks for efficient client-side lazy loading on the static site.
"""
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

from utils import write_json_file, ensure_directory_exists

logger = logging.getLogger('cnascorecard.chunking')


def write_chunked_cna_data(
    cna_list: List[Dict[str, Any]], 
    output_dir: Path,
    chunk_size: int = 50
) -> Dict[str, Any]:
    """
    Split CNA data into static chunks for lazy loading.
    
    This creates multiple JSON files that can be loaded on-demand by the
    web interface, improving initial page load time for large datasets.
    
    Args:
        cna_list: List of CNA data dictionaries (sorted by desired order)
        output_dir: Base output directory (chunks go in output_dir/chunks/)
        chunk_size: Number of CNAs per chunk (default 50)
        
    Returns:
        Manifest dictionary with chunking metadata
        
    Example:
        >>> manifest = write_chunked_cna_data(cna_list, Path("web/data"))
        >>> print(f"Created {manifest['totalChunks']} chunks")
    """
    chunks_dir = output_dir / "chunks"
    ensure_directory_exists(chunks_dir)
    
    total_cnas = len(cna_list)
    total_chunks = (total_cnas + chunk_size - 1) // chunk_size
    
    logger.info(f"Creating {total_chunks} CNA chunks of ~{chunk_size} items each")
    
    chunk_files = []
    
    for i in range(0, total_cnas, chunk_size):
        chunk_index = i // chunk_size
        chunk = cna_list[i:i + chunk_size]
        chunk_file = f"cna_chunk_{chunk_index}.json"
        chunk_path = chunks_dir / chunk_file
        
        # Write chunk with metadata
        chunk_data = {
            "chunkIndex": chunk_index,
            "startIndex": i,
            "endIndex": min(i + chunk_size, total_cnas),
            "count": len(chunk),
            "items": chunk
        }
        
        write_json_file(chunk_data, chunk_path)
        chunk_files.append(chunk_file)
        
        logger.debug(f"Wrote chunk {chunk_index}: {len(chunk)} CNAs")
    
    # Write manifest for client-side loader
    manifest = {
        "totalCNAs": total_cnas,
        "chunkSize": chunk_size,
        "totalChunks": total_chunks,
        "chunks": chunk_files,
        "generatedAt": _get_timestamp()
    }
    
    manifest_path = chunks_dir / "manifest.json"
    write_json_file(manifest, manifest_path)
    
    logger.info(f"Created chunk manifest at {manifest_path}")
    
    return manifest


def write_chunked_completeness_data(
    completeness_list: List[Dict[str, Any]],
    output_dir: Path,
    chunk_size: int = 100
) -> Dict[str, Any]:
    """
    Split completeness data into chunks for lazy loading.
    
    Args:
        completeness_list: List of CNA completeness data
        output_dir: Base output directory
        chunk_size: Number of items per chunk
        
    Returns:
        Manifest dictionary
    """
    chunks_dir = output_dir / "completeness" / "chunks"
    ensure_directory_exists(chunks_dir)
    
    total_items = len(completeness_list)
    total_chunks = (total_items + chunk_size - 1) // chunk_size
    
    chunk_files = []
    
    for i in range(0, total_items, chunk_size):
        chunk_index = i // chunk_size
        chunk = completeness_list[i:i + chunk_size]
        chunk_file = f"completeness_chunk_{chunk_index}.json"
        chunk_path = chunks_dir / chunk_file
        
        chunk_data = {
            "chunkIndex": chunk_index,
            "startIndex": i,
            "endIndex": min(i + chunk_size, total_items),
            "count": len(chunk),
            "items": chunk
        }
        
        write_json_file(chunk_data, chunk_path)
        chunk_files.append(chunk_file)
    
    manifest = {
        "totalItems": total_items,
        "chunkSize": chunk_size,
        "totalChunks": total_chunks,
        "chunks": chunk_files,
        "generatedAt": _get_timestamp()
    }
    
    manifest_path = chunks_dir / "manifest.json"
    write_json_file(manifest, manifest_path)
    
    return manifest


def generate_search_index(
    cna_list: List[Dict[str, Any]],
    output_dir: Path
) -> Dict[str, Any]:
    """
    Generate a search index for client-side filtering.
    
    This creates a lightweight index that can be loaded once and used
    for instant filtering without fetching all data chunks.
    
    Args:
        cna_list: List of CNA data dictionaries
        output_dir: Output directory for the index file
        
    Returns:
        Search index dictionary
    """
    logger.info("Generating search index")
    
    # Extract searchable fields
    cna_names = []
    cna_ids = []
    types = set()
    grades = set()
    countries = set()
    
    for cna in cna_list:
        short_name = cna.get("shortName", "")
        if short_name:
            cna_names.append(short_name)
        
        cna_id = cna.get("cnaId", "")
        if cna_id:
            cna_ids.append(cna_id)
        
        cna_type = cna.get("type", "")
        if cna_type:
            types.add(cna_type)
        
        grade = cna.get("grade", "")
        if grade:
            grades.add(grade)
        
        country = cna.get("country", "")
        if country:
            countries.add(country)
    
    search_index = {
        "cnaNames": sorted(cna_names),
        "cnaIds": cna_ids,
        "types": sorted(types),
        "grades": sorted(grades, key=_grade_sort_key),
        "countries": sorted(countries),
        "totalCNAs": len(cna_list),
        "generatedAt": _get_timestamp()
    }
    
    index_path = output_dir / "search_index.json"
    write_json_file(search_index, index_path)
    
    logger.info(f"Generated search index with {len(cna_names)} CNAs")
    
    return search_index


def generate_summary_stats(
    cna_list: List[Dict[str, Any]],
    output_dir: Path
) -> Dict[str, Any]:
    """
    Generate summary statistics for dashboard cards.
    
    This creates a small file with aggregate stats that can be loaded
    instantly for the main dashboard.
    
    Args:
        cna_list: List of CNA data dictionaries
        output_dir: Output directory
        
    Returns:
        Summary statistics dictionary
    """
    total_cnas = len(cna_list)
    total_cves = sum(cna.get("cveCount", 0) for cna in cna_list)
    
    # Grade distribution
    grade_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    for cna in cna_list:
        grade = cna.get("grade", "F")
        if grade in grade_counts:
            grade_counts[grade] += 1
    
    # Score distribution
    scores = [cna.get("overallScore", 0) for cna in cna_list if cna.get("overallScore")]
    avg_score = sum(scores) / len(scores) if scores else 0
    
    # Type distribution
    type_counts = {}
    for cna in cna_list:
        cna_type = cna.get("type", "Unknown")
        type_counts[cna_type] = type_counts.get(cna_type, 0) + 1
    
    # Trend summary
    trend_counts = {"up": 0, "down": 0, "steady": 0}
    for cna in cna_list:
        trend = cna.get("trend", "steady")
        if trend in trend_counts:
            trend_counts[trend] += 1
    
    stats = {
        "totalCNAs": total_cnas,
        "totalCVEs": total_cves,
        "averageScore": round(avg_score, 1),
        "gradeDistribution": grade_counts,
        "typeDistribution": type_counts,
        "trendDistribution": trend_counts,
        "generatedAt": _get_timestamp()
    }
    
    stats_path = output_dir / "summary_stats.json"
    write_json_file(stats, stats_path)
    
    logger.info(f"Generated summary stats: {total_cnas} CNAs, {total_cves} CVEs")
    
    return stats


def cleanup_old_chunks(chunks_dir: Path, keep_latest: int = 1) -> int:
    """
    Clean up old chunk files.
    
    Args:
        chunks_dir: Directory containing chunk files
        keep_latest: Number of generations to keep (default 1)
        
    Returns:
        Number of files removed
    """
    if not chunks_dir.exists():
        return 0
    
    # For now, just remove all chunk files (they get regenerated each run)
    removed = 0
    for chunk_file in chunks_dir.glob("*_chunk_*.json"):
        try:
            chunk_file.unlink()
            removed += 1
        except OSError:
            pass
    
    if removed > 0:
        logger.debug(f"Cleaned up {removed} old chunk files")
    
    return removed


def _get_timestamp() -> str:
    """Get current UTC timestamp in ISO format."""
    from datetime import datetime
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _grade_sort_key(grade: str) -> int:
    """Sort key for grades (A=0, B=1, etc)."""
    order = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
    return order.get(grade, 5)
