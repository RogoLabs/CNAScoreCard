"""
Utility functions for CNA Scorecard Pipeline.

This module provides common utility functions including logging setup,
file operations, and data validation helpers.
"""
import logging
import logging.config
from typing import Any, Dict, Optional
from pathlib import Path
import json
import os

from config import LOGGING_CONFIG


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    """
    Set up logging configuration for the pipeline.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured logger instance
    """
    # Update log level in config
    config = LOGGING_CONFIG.copy()
    config['handlers']['console']['level'] = log_level
    
    # Configure logging
    logging.config.dictConfig(config)
    
    # Return logger for the pipeline
    return logging.getLogger('cnascorecard')


def ensure_directory_exists(directory_path: Path) -> None:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        directory_path: Path to the directory
        
    Raises:
        OSError: If directory cannot be created
    """
    try:
        directory_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise OSError(f"Failed to create directory {directory_path}: {e}")


def load_json_file(file_path: Path) -> Dict[str, Any]:
    """
    Load and parse a JSON file with proper error handling.
    
    Args:
        file_path: Path to the JSON file
        
    Returns:
        Parsed JSON data
        
    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If JSON is invalid
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"JSON file not found: {file_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in file {file_path}: {e}")


def write_json_file(data: Any, file_path: Path, indent: int = 2) -> None:
    """
    Write data to a JSON file with proper error handling.
    
    Args:
        data: Data to write
        file_path: Path to the output file
        indent: JSON indentation level
        
    Raises:
        OSError: If file cannot be written
    """
    try:
        # Ensure parent directory exists
        ensure_directory_exists(file_path.parent)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
    except OSError as e:
        raise OSError(f"Failed to write JSON file {file_path}: {e}")


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by replacing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename safe for filesystem use
    """
    # Replace invalid characters with underscores
    invalid_chars = '<>:"/\\|?*'
    sanitized = filename
    for char in invalid_chars:
        sanitized = sanitized.replace(char, '_')
    
    # Remove leading/trailing whitespace and dots
    sanitized = sanitized.strip(' .')
    
    # Ensure filename is not empty
    if not sanitized:
        sanitized = "unknown"
    
    # Limit length to 255 characters (common filesystem limit)
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    
    return sanitized


def validate_cve_record(cve: Dict[str, Any]) -> bool:
    """
    Validate that a CVE record has the minimum required structure.
    
    Args:
        cve: CVE record dictionary
        
    Returns:
        True if valid, False otherwise
    """
    if not isinstance(cve, dict):
        return False
    
    # Check for required top-level structure
    if "cveMetadata" not in cve:
        return False
    
    cve_metadata = cve.get("cveMetadata", {})
    if not isinstance(cve_metadata, dict):
        return False
    
    # Check for required metadata fields
    if "cveId" not in cve_metadata:
        return False
    
    # Check for CNA container
    containers = cve.get("containers", {})
    if not isinstance(containers, dict):
        return False
    
    cna = containers.get("cna", {})
    if not isinstance(cna, dict):
        return False
    
    return True


def extract_cna_short_name(cve: Dict[str, Any]) -> Optional[str]:
    """
    Extract CNA short name from a CVE record.
    
    Args:
        cve: CVE record dictionary
        
    Returns:
        CNA short name if found, None otherwise
    """
    try:
        containers = cve.get("containers", {})
        cna = containers.get("cna", {})
        provider = cna.get("providerMetadata", {})
        return provider.get("shortName")
    except (AttributeError, TypeError):
        return None


def get_nested_value(data: Dict[str, Any], path: list) -> Any:
    """
    Get a nested value from a dictionary using a path list.
    
    Args:
        data: Dictionary to search
        path: List of keys representing the path
        
    Returns:
        Value at the path, or None if not found
    """
    current = data
    try:
        for key in path:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current
    except (TypeError, KeyError):
        return None


def calculate_percentage(numerator: int, denominator: int, decimal_places: int = 1) -> float:
    """
    Calculate percentage with proper handling of division by zero.
    
    Args:
        numerator: Numerator value
        denominator: Denominator value
        decimal_places: Number of decimal places to round to
        
    Returns:
        Percentage value, 0.0 if denominator is zero
    """
    if denominator == 0:
        return 0.0
    
    percentage = (numerator / denominator) * 100
    return round(percentage, decimal_places)


def format_date_string(date_str: str) -> str:
    """
    Format a date string to ensure consistent format.
    
    Args:
        date_str: Date string in various formats
        
    Returns:
        Formatted date string in YYYY-MM-DD format, or original if parsing fails
    """
    if not date_str:
        return ""
    
    # Handle ISO format with timezone
    if 'T' in date_str:
        date_str = date_str.split('T')[0]
    
    # Return first 10 characters (YYYY-MM-DD)
    return date_str[:10] if len(date_str) >= 10 else date_str


class ProgressTracker:
    """Simple progress tracker for long-running operations."""
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.logger = logging.getLogger('cnascorecard.progress')
    
    def update(self, increment: int = 1) -> None:
        """Update progress counter."""
        self.current += increment
        if self.current % max(1, self.total // 10) == 0 or self.current == self.total:
            percentage = (self.current / self.total) * 100
            self.logger.info(f"{self.description}: {self.current}/{self.total} ({percentage:.1f}%)")
    
    def finish(self) -> None:
        """Mark progress as complete."""
        self.logger.info(f"{self.description}: Complete ({self.total} items processed)")
