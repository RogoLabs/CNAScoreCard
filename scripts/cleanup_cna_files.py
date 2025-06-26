#!/usr/bin/env python3
"""
Cleanup script to remove individual CNA HTML files that are no longer needed.
The system now uses cna-detail.html as a unified page for all CNAs.
"""

import os
import glob
from pathlib import Path

def cleanup_cna_files():
    """Remove individual CNA HTML files from web/cna folder."""
    cna_dir = Path("web/cna")
    
    if not cna_dir.exists():
        print("web/cna directory not found")
        return
    
    # Files to keep (essential files for the unified system)
    keep_files = {
        'cna-detail.html',
        'cna-script.js', 
        'cna-styles.css',
        'index.html'
    }
    
    # Keep the data directory
    keep_dirs = {'data'}
    
    removed_count = 0
    
    # Get all files in the cna directory
    for item in cna_dir.iterdir():
        if item.is_file():
            if item.name not in keep_files:
                print(f"Removing: {item}")
                item.unlink()
                removed_count += 1
            else:
                print(f"Keeping: {item.name}")
        elif item.is_dir():
            if item.name not in keep_dirs:
                print(f"Would remove directory: {item.name} (not implemented for safety)")
            else:
                print(f"Keeping directory: {item.name}")
    
    print(f"\nCleanup complete! Removed {removed_count} individual CNA HTML files.")
    print("The system now uses cna-detail.html as a unified page for all CNAs.")

if __name__ == "__main__":
    cleanup_cna_files()