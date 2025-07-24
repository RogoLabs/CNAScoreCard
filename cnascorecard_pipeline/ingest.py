"""
ingest.py: Load CVE and CNA data from cve_data directory (CVE5 format).

This module provides functions to load and validate CVE records from the filesystem,
with support for date filtering and CNA extraction.
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from glob import glob

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
        recent_years = ['2024', '2025']
        
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
    end_date: Optional[str]
) -> List[Dict[str, Any]]:
    """
    Load CVE files and apply date filtering.
    
    Args:
        cve_files: List of CVE file paths
        start_date: Start date filter
        end_date: End date filter
        
    Returns:
        List of filtered CVE records
    """
    progress = ProgressTracker(len(cve_files), "Loading CVE files")
    records = []
    
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


def _load_single_cve_file(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Load and validate a single CVE file.
    
    Args:
        file_path: Path to CVE file
        
    Returns:
        CVE record dictionary if valid, None otherwise
    """
    try:
        data = load_json_file(Path(file_path))
        
        # Validate CVE record structure
        if not validate_cve_record(data):
            return None
        
        # Filter out rejected CVEs
        cve_state = data.get("cveMetadata", {}).get("state")
        if cve_state == "REJECTED":
            return None
        
        return data
        
    except Exception as e:
        logger.debug(f"Error loading CVE file {file_path}: {e}")
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
