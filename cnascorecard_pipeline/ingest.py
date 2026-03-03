"""
ingest.py: Load CVE and CNA data from cve_data directory (CVE5 format).

This module provides functions to load and validate CVE records from the filesystem,
with support for date filtering, CNA extraction, and parallel processing.
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from glob import glob
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
import os

from config import CVE_DATA_DIR, DATE_FORMAT
from utils import load_json_file, validate_cve_record, extract_cna_short_name, ProgressTracker

# Initialize logging
logger = logging.getLogger('cnascorecard.ingest')

def load_cve_records(
    cve_dir: Optional[str] = None, 
    start_date: Optional[str] = None, 
    end_date: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Load CVE JSON records from the cve_data directory, optionally filtering by datePublished.
    
    Args:
        cve_dir: Path to CVE data directory (defaults to config value)
        start_date: Start date filter in 'YYYY-MM-DD' format
        end_date: End date filter in 'YYYY-MM-DD' format
        
    Returns:
        List of CVE record dictionaries
        
    Note:
        When date filtering is provided, searches all year folders since CVEs can be published
        in any year regardless of their CVE identifier year (e.g., CVE-2015 published in 2025).
    """
    if cve_dir is None:
        cve_dir = str(CVE_DATA_DIR)
    
    logger.info(f"Loading CVE records from {cve_dir}")
    if start_date or end_date:
        logger.info(f"Date filtering: {start_date} to {end_date}")
    
    # Get list of CVE files to process
    cve_files = _get_cve_file_list(cve_dir, start_date, end_date)
    
    if not cve_files:
        logger.warning("No CVE files found to process")
        return []
    
    logger.info(f"Processing {len(cve_files)} CVE files")
    
    # Load and filter CVE records
    records = _load_and_filter_cves(cve_files, start_date, end_date)
    
    logger.info(f"Successfully loaded {len(records)} CVE records")
    return records


def _get_cve_file_list(
    cve_dir: str, 
    start_date: Optional[str], 
    end_date: Optional[str]
) -> List[str]:
    """
    Get list of CVE files to process based on filtering requirements.
    
    Args:
        cve_dir: Path to CVE data directory
        start_date: Start date filter
        end_date: End date filter
        
    Returns:
        List of CVE file paths
    """
    cve_files = []
    cves_dir = Path(cve_dir) / "cves"
    
    if not cves_dir.exists():
        logger.error(f"CVE directory not found: {cves_dir}")
        return []
    
    if start_date or end_date:
        # When date filtering is needed, check all year folders
        logger.info("Date filtering requested - scanning all CVE year folders")
        year_dirs = _get_year_directories(cves_dir)
        
        for year in year_dirs:
            year_files = _get_year_files(cves_dir, year)
            cve_files.extend(year_files)
            logger.debug(f"Found {len(year_files)} CVE files in {year}")
    else:
        # When no date filtering, optimize by only loading recent years
        logger.info("No date filtering - optimizing by loading recent years only")
        recent_years = [str(datetime.now().year), str(datetime.now().year - 1)]
        
        for year in recent_years:
            if (cves_dir / year).exists():
                year_files = _get_year_files(cves_dir, year)
                cve_files.extend(year_files)
                logger.debug(f"Found {len(year_files)} CVE files in {year}")
    
    return cve_files


def _get_year_directories(cves_dir: Path) -> List[str]:
    """
    Get sorted list of year directories in CVE data directory.
    
    Args:
        cves_dir: Path to cves directory
        
    Returns:
        Sorted list of year directory names
    """
    try:
        year_dirs = [
            d.name for d in cves_dir.iterdir() 
            if d.is_dir() and d.name.isdigit()
        ]
        return sorted(year_dirs)
    except OSError as e:
        logger.error(f"Error reading year directories from {cves_dir}: {e}")
        return []


def _get_year_files(cves_dir: Path, year: str) -> List[str]:
    """
    Get all CVE files for a specific year.
    
    Args:
        cves_dir: Path to cves directory
        year: Year directory name
        
    Returns:
        List of CVE file paths for the year
    """
    year_pattern = str(cves_dir / year / "**" / "CVE-*.json")
    return glob(year_pattern, recursive=True)


def _load_and_filter_cves(
    cve_files: List[str], 
    start_date: Optional[str], 
    end_date: Optional[str],
    use_parallel: bool = True,
    max_workers: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Load CVE files and apply date filtering.
    
    Args:
        cve_files: List of CVE file paths
        start_date: Start date filter
        end_date: End date filter
        use_parallel: Whether to use parallel processing (default True)
        max_workers: Number of worker processes (default: CPU count, max 8)
        
    Returns:
        List of filtered CVE records
    """
    # Parse date filters
    start_dt = None
    end_dt = None
    
    if start_date:
        try:
            start_dt = datetime.strptime(start_date, DATE_FORMAT)
        except ValueError as e:
            logger.error(f"Invalid start date format '{start_date}': {e}")
            return []
    
    if end_date:
        try:
            end_dt = datetime.strptime(end_date, DATE_FORMAT)
        except ValueError as e:
            logger.error(f"Invalid end date format '{end_date}': {e}")
            return []
    
    # Choose parallel or sequential processing
    if use_parallel and len(cve_files) > 100:
        return _load_cves_parallel(cve_files, start_dt, end_dt, max_workers)
    else:
        return _load_cves_sequential(cve_files, start_dt, end_dt)


def _load_cves_sequential(
    cve_files: List[str],
    start_dt: Optional[datetime],
    end_dt: Optional[datetime]
) -> List[Dict[str, Any]]:
    """Load CVE files sequentially (original method)."""
    progress = ProgressTracker(len(cve_files), "Loading CVE files")
    records = []
    
    for file_path in cve_files:
        try:
            cve_record = _load_single_cve_file(file_path)
            if cve_record and _passes_date_filter(cve_record, start_dt, end_dt):
                records.append(cve_record)
        except Exception as e:
            logger.debug(f"Skipping file {file_path}: {e}")
        finally:
            progress.update()
    
    progress.finish()
    return records


def _load_cves_parallel(
    cve_files: List[str],
    start_dt: Optional[datetime],
    end_dt: Optional[datetime],
    max_workers: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Load CVE files using parallel processing for improved performance.
    
    Args:
        cve_files: List of CVE file paths
        start_dt: Start date filter (datetime object)
        end_dt: End date filter (datetime object)
        max_workers: Number of worker processes
        
    Returns:
        List of filtered CVE records
    """
    if max_workers is None:
        max_workers = min(multiprocessing.cpu_count(), 8)
    
    logger.info(f"Loading {len(cve_files)} CVE files using {max_workers} workers")
    
    # Convert datetime to string for pickling across processes
    start_str = start_dt.strftime(DATE_FORMAT) if start_dt else None
    end_str = end_dt.strftime(DATE_FORMAT) if end_dt else None
    
    records = []
    failed_count = 0
    
    # Process files in batches to reduce overhead
    batch_size = max(100, len(cve_files) // (max_workers * 4))
    batches = [cve_files[i:i + batch_size] for i in range(0, len(cve_files), batch_size)]
    
    logger.info(f"Processing in {len(batches)} batches of ~{batch_size} files each")
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_load_cve_batch, batch, start_str, end_str): i 
            for i, batch in enumerate(batches)
        }
        
        for future in as_completed(futures):
            try:
                batch_records, batch_failed = future.result()
                records.extend(batch_records)
                failed_count += batch_failed
            except Exception as e:
                logger.error(f"Batch processing error: {e}")
    
    logger.info(f"Parallel loading complete: {len(records)} records loaded, {failed_count} files skipped")
    return records


def _load_cve_batch(
    file_paths: List[str],
    start_date_str: Optional[str],
    end_date_str: Optional[str]
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Load a batch of CVE files (designed to run in a worker process).
    
    Args:
        file_paths: List of CVE file paths to load
        start_date_str: Start date filter string (YYYY-MM-DD)
        end_date_str: End date filter string (YYYY-MM-DD)
        
    Returns:
        Tuple of (list of valid CVE records, count of failed files)
    """
    # Import inside function to avoid pickling issues
    import json
    from datetime import datetime
    
    DATE_FMT = "%Y-%m-%d"
    
    # Parse dates in worker process
    start_dt = datetime.strptime(start_date_str, DATE_FMT) if start_date_str else None
    end_dt = datetime.strptime(end_date_str, DATE_FMT) if end_date_str else None
    
    records = []
    failed = 0
    
    for file_path in file_paths:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Basic validation
            if not isinstance(data, dict):
                failed += 1
                continue
                
            if "cveMetadata" not in data or "containers" not in data:
                failed += 1
                continue
            
            # Skip rejected CVEs
            if data.get("cveMetadata", {}).get("state") == "REJECTED":
                continue
            
            # Date filtering
            pub_date_str = data.get("cveMetadata", {}).get("datePublished")
            if pub_date_str:
                pub_date_clean = pub_date_str[:10]
                try:
                    pub_dt = datetime.strptime(pub_date_clean, DATE_FMT)
                    
                    if start_dt and pub_dt < start_dt:
                        continue
                    if end_dt and pub_dt > end_dt:
                        continue
                except ValueError:
                    # If date parsing fails, include the record
                    pass
            elif start_dt or end_dt:
                # No publication date but filter requested - skip
                continue
            
            records.append(data)
            
        except Exception:
            failed += 1
    
    return records, failed


def _load_single_cve_file(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Load and validate a single CVE file with comprehensive error handling.
    
    Args:
        file_path: Path to CVE file
        
    Returns:
        CVE record dictionary if valid, None otherwise
        
    Note:
        This function gracefully handles various error conditions:
        - File not found or permissions errors
        - Invalid JSON syntax
        - Missing required CVE fields (cveMetadata, containers)
        - Rejected CVE state
        - Unsupported schema versions (logs warning but still loads)
    """
    try:
        data = load_json_file(Path(file_path))
        
        # Validate CVE record structure
        if not validate_cve_record(data):
            logger.debug(f"Invalid CVE structure in {file_path}")
            return None
        
        # Filter out rejected CVEs
        cve_state = data.get("cveMetadata", {}).get("state")
        if cve_state == "REJECTED":
            return None
        
        # Check schema version (informational, don't reject)
        data_version = data.get("dataVersion", "unknown")
        from config import SUPPORTED_SCHEMA_VERSIONS
        if data_version not in SUPPORTED_SCHEMA_VERSIONS:
            cve_id = data.get("cveMetadata", {}).get("cveId", "unknown")
            logger.warning(f"CVE {cve_id} uses unsupported schema version: {data_version}")
        
        return data
        
    except FileNotFoundError:
        logger.debug(f"CVE file not found: {file_path}")
        return None
    except PermissionError:
        logger.warning(f"Permission denied reading CVE file: {file_path}")
        return None
    except ValueError as e:
        # Invalid JSON
        logger.debug(f"Invalid JSON in CVE file {file_path}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error loading CVE file {file_path}: {type(e).__name__}: {e}")
        return None


def _passes_date_filter(
    cve: Dict[str, Any], 
    start_dt: Optional[datetime], 
    end_dt: Optional[datetime]
) -> bool:
    """
    Check if CVE record passes date filtering criteria.
    
    Args:
        cve: CVE record dictionary
        start_dt: Start date filter
        end_dt: End date filter
        
    Returns:
        True if CVE passes date filter, False otherwise
    """
    if not start_dt and not end_dt:
        return True
    
    pub_date_str = cve.get("cveMetadata", {}).get("datePublished")
    if not pub_date_str:
        return False
    
    try:
        # Handle ISO format dates
        pub_date_clean = pub_date_str[:10]  # Take YYYY-MM-DD part
        pub_dt = datetime.strptime(pub_date_clean, DATE_FORMAT)
        
        if start_dt and pub_dt < start_dt:
            return False
        
        if end_dt and pub_dt > end_dt:
            return False
        
        return True
        
    except ValueError as e:
        logger.debug(f"Invalid date format in CVE {cve.get('cveId', 'unknown')}: {pub_date_str}")
        return False

def load_cna_list(cve_records: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Extract unique CNA shortNames from CVE records.
    
    Args:
        cve_records: List of CVE record dictionaries
        
    Returns:
        List of CNA dictionaries with shortName field
    """
    if not cve_records:
        logger.warning("No CVE records provided for CNA extraction")
        return []
    
    logger.info(f"Extracting CNA information from {len(cve_records)} CVE records")
    
    cna_set = set()
    for cve in cve_records:
        short_name = extract_cna_short_name(cve)
        if short_name:
            cna_set.add(short_name)
    
    cna_list = [{"shortName": name} for name in sorted(cna_set)]
    logger.info(f"Found {len(cna_list)} unique CNAs")
    
    return cna_list


def get_date_range_for_period(months_back: int = 6) -> Tuple[str, str]:
    """
    Get date range for a specific period back from current date.
    
    Args:
        months_back: Number of months to go back from current date
        
    Returns:
        Tuple of (start_date, end_date) in YYYY-MM-DD format
    """
    from datetime import date, timedelta
    from dateutil.relativedelta import relativedelta
    
    end_date = date.today()
    start_date = end_date - relativedelta(months=months_back)
    
    return start_date.strftime(DATE_FORMAT), end_date.strftime(DATE_FORMAT)


def validate_date_range(start_date: str, end_date: str) -> bool:
    """
    Validate that date range is properly formatted and logical.
    
    Args:
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format
        
    Returns:
        True if date range is valid, False otherwise
    """
    try:
        start_dt = datetime.strptime(start_date, DATE_FORMAT)
        end_dt = datetime.strptime(end_date, DATE_FORMAT)
        
        if start_dt > end_dt:
            logger.error(f"Start date {start_date} is after end date {end_date}")
            return False
        
        return True
        
    except ValueError as e:
        logger.error(f"Invalid date format: {e}")
        return False

# =============================================================================
# Delta Processing Functions
# =============================================================================

def load_delta_cves(
    cve_dir: Optional[str] = None,
    since: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """
    Load only new and updated CVEs from delta files.
    
    This function uses the delta.json and deltaLog.json files to identify
    CVEs that have changed since the last run, enabling incremental processing.
    
    Args:
        cve_dir: Path to CVE data directory (defaults to config value)
        since: ISO timestamp to filter changes after (e.g., "2025-10-28T00:00:00Z")
               If None, only the latest delta.json is used.
        
    Returns:
        Tuple of:
        - List of new CVE records
        - List of updated CVE records
        - Metadata dict with fetchTime, numberOfChanges, errors
        
    Example:
        >>> new_cves, updated_cves, meta = load_delta_cves()
        >>> print(f"Found {len(new_cves)} new, {len(updated_cves)} updated")
    """
    if cve_dir is None:
        cve_dir = str(CVE_DATA_DIR)
    
    cves_dir = Path(cve_dir) / "cves"
    delta_file = cves_dir / "delta.json"
    delta_log_file = cves_dir / "deltaLog.json"
    
    new_records = []
    updated_records = []
    metadata = {
        "fetchTime": None,
        "numberOfChanges": 0,
        "errors": []
    }
    
    # Collect delta entries to process
    delta_entries = []
    
    if since:
        # Load from deltaLog for historical changes
        delta_entries = _get_delta_entries_since(delta_log_file, since)
        logger.info(f"Found {len(delta_entries)} delta entries since {since}")
    else:
        # Just use latest delta.json
        if delta_file.exists():
            try:
                delta_data = load_json_file(delta_file)
                delta_entries = [delta_data]
                logger.info(f"Loaded latest delta with {delta_data.get('numberOfChanges', 0)} changes")
            except Exception as e:
                logger.error(f"Error loading delta.json: {e}")
                metadata["errors"].append(str(e))
    
    if not delta_entries:
        logger.warning("No delta entries found to process")
        return new_records, updated_records, metadata
    
    # Process each delta entry
    all_new_cve_ids = set()
    all_updated_cve_ids = set()
    
    for delta in delta_entries:
        fetch_time = delta.get("fetchTime")
        if metadata["fetchTime"] is None:
            metadata["fetchTime"] = fetch_time
        
        # Collect CVE IDs
        for cve_entry in delta.get("new", []):
            all_new_cve_ids.add(cve_entry.get("cveId"))
        
        for cve_entry in delta.get("updated", []):
            all_updated_cve_ids.add(cve_entry.get("cveId"))
        
        # Track errors
        for error in delta.get("error", []):
            metadata["errors"].append(error)
    
    # Remove any CVE from "new" if it also appears in "updated" (was updated after creation)
    all_new_cve_ids -= all_updated_cve_ids
    
    logger.info(f"Processing {len(all_new_cve_ids)} new CVEs and {len(all_updated_cve_ids)} updated CVEs")
    
    # Load the actual CVE records
    new_records = _load_cves_by_id(cves_dir, list(all_new_cve_ids))
    updated_records = _load_cves_by_id(cves_dir, list(all_updated_cve_ids))
    
    metadata["numberOfChanges"] = len(new_records) + len(updated_records)
    
    return new_records, updated_records, metadata


def _get_delta_entries_since(delta_log_file: Path, since: str) -> List[Dict[str, Any]]:
    """
    Get delta entries from deltaLog.json since a specific timestamp.
    
    Args:
        delta_log_file: Path to deltaLog.json
        since: ISO timestamp to filter from
        
    Returns:
        List of delta entries with fetchTime >= since
    """
    if not delta_log_file.exists():
        logger.warning(f"Delta log file not found: {delta_log_file}")
        return []
    
    try:
        since_dt = datetime.fromisoformat(since.replace('Z', '+00:00'))
    except ValueError as e:
        logger.error(f"Invalid 'since' timestamp format: {since}")
        return []
    
    entries = []
    try:
        delta_log = load_json_file(delta_log_file)
        
        if not isinstance(delta_log, list):
            logger.error("deltaLog.json is not a list")
            return []
        
        for entry in delta_log:
            fetch_time_str = entry.get("fetchTime")
            if fetch_time_str:
                try:
                    fetch_dt = datetime.fromisoformat(fetch_time_str.replace('Z', '+00:00'))
                    if fetch_dt >= since_dt:
                        entries.append(entry)
                except ValueError:
                    continue
        
        return entries
        
    except Exception as e:
        logger.error(f"Error reading deltaLog.json: {e}")
        return []


def _load_cves_by_id(cves_dir: Path, cve_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Load CVE records by their CVE IDs.
    
    Args:
        cves_dir: Path to cves directory
        cve_ids: List of CVE IDs to load (e.g., ["CVE-2025-10150", "CVE-2025-10151"])
        
    Returns:
        List of loaded CVE records
    """
    records = []
    
    for cve_id in cve_ids:
        if not cve_id:
            continue
            
        file_path = _cve_id_to_path(cves_dir, cve_id)
        if file_path and file_path.exists():
            record = _load_single_cve_file(str(file_path))
            if record:
                records.append(record)
        else:
            logger.debug(f"CVE file not found for {cve_id}")
    
    return records


def _cve_id_to_path(cves_dir: Path, cve_id: str) -> Optional[Path]:
    """
    Convert a CVE ID to its file path.
    
    CVE IDs follow the pattern CVE-YYYY-NNNNN where:
    - YYYY is the year
    - NNNNN is a sequence number (variable length)
    
    Files are organized as: cves/YYYY/Nxxx/CVE-YYYY-NNNNN.json
    
    Args:
        cves_dir: Path to cves directory
        cve_id: CVE ID (e.g., "CVE-2025-10150")
        
    Returns:
        Path to CVE file, or None if invalid ID
    """
    if not cve_id or not cve_id.startswith("CVE-"):
        return None
    
    parts = cve_id.split("-")
    if len(parts) != 3:
        return None
    
    try:
        year = parts[1]
        seq_num = parts[2]
        
        # Determine the subdirectory (e.g., "10xxx" for 10150)
        if len(seq_num) <= 4:
            subdir = f"{seq_num[0]}xxx"
        else:
            # For longer sequence numbers (e.g., 10150 -> 10xxx)
            subdir = f"{seq_num[:-3]}xxx"
        
        return cves_dir / year / subdir / f"{cve_id}.json"
        
    except (IndexError, ValueError) as e:
        logger.debug(f"Invalid CVE ID format: {cve_id}")
        return None


def get_last_run_timestamp(state_file: Path) -> Optional[str]:
    """
    Get the timestamp of the last successful pipeline run.
    
    Args:
        state_file: Path to state file storing last run info
        
    Returns:
        ISO timestamp string of last run, or None if no previous run
    """
    if not state_file.exists():
        return None
    
    try:
        state = load_json_file(state_file)
        return state.get("last_run_timestamp")
    except Exception as e:
        logger.warning(f"Error reading state file: {e}")
        return None


def save_run_timestamp(state_file: Path, timestamp: Optional[str] = None) -> None:
    """
    Save the current timestamp as the last run time.
    
    Args:
        state_file: Path to state file
        timestamp: ISO timestamp to save (defaults to current time)
    """
    import json
    
    if timestamp is None:
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    
    state = {
        "last_run_timestamp": timestamp,
        "updated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    }
    
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
        logger.info(f"Saved run timestamp: {timestamp}")
    except Exception as e:
        logger.error(f"Error saving state file: {e}")


def main() -> None:
    """
    Main function for testing ingest functionality.
    """
    from utils import setup_logging
    
    # Setup logging for testing
    setup_logging("INFO")
    
    # Test basic loading
    logger.info("Testing CVE record loading...")
    records = load_cve_records()
    logger.info(f"Loaded {len(records)} CVE records")
    
    # Test CNA extraction
    cna_list = load_cna_list(records)
    logger.info(f"Found {len(cna_list)} unique CNAs")
    
    # Test date filtering
    start_date, end_date = get_date_range_for_period(6)
    logger.info(f"Testing date filtering for period: {start_date} to {end_date}")
    
    filtered_records = load_cve_records(start_date=start_date, end_date=end_date)
    logger.info(f"Loaded {len(filtered_records)} CVE records with date filtering")


if __name__ == "__main__":
    main()
