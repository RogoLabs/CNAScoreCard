#!/usr/bin/env python3
"""
Cleanup script to remove orphaned CNA HTML files from web/cna/ directory.
This script identifies HTML files that don't have corresponding data files
or aren't referenced in the current CNA data.
"""

import os
import json
import sys
from pathlib import Path

def load_cna_data():
    """Load the current CNA data to get list of active CNAs."""
    try:
        cna_data_file = Path("web/data/cnas.json")
        if not cna_data_file.exists():
            print("Error: web/data/cnas.json not found. Run generate_static_data.py first.")
            return None
        
        with open(cna_data_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading CNA data: {e}")
        return None

def get_valid_cna_names(cna_data):
    """Extract valid CNA names from the data."""
    valid_names = set()
    
    for cna in cna_data:
        cna_name = cna.get('cna', '').strip()
        if cna_name:
            # Create safe filename like the generation scripts do
            safe_filename = "".join(c for c in cna_name if c.isalnum() or c in (' ', '-', '_')).strip()
            safe_filename = safe_filename.replace(' ', '_')
            valid_names.add(safe_filename)
    
    return valid_names

def get_existing_html_files():
    """Get all HTML files in the web/cna/ directory."""
    cna_dir = Path("web/cna")
    if not cna_dir.exists():
        print("Error: web/cna directory not found.")
        return set()
    
    html_files = set()
    for file_path in cna_dir.glob("*.html"):
        # Skip special files
        if file_path.name in ['index.html', 'cna-detail.html']:
            continue
        
        # Get filename without extension
        filename = file_path.stem
        html_files.add(filename)
    
    return html_files

def get_existing_data_files():
    """Get all JSON data files in the web/cna/data/ directory."""
    data_dir = Path("web/cna/data")
    if not data_dir.exists():
        return set()
    
    data_files = set()
    for file_path in data_dir.glob("*.json"):
        filename = file_path.stem
        data_files.add(filename)
    
    return data_files

def find_orphaned_files(valid_names, html_files, data_files):
    """Find files that should be removed."""
    # Files that exist as HTML but don't have valid CNA data
    orphaned_html = html_files - valid_names
    
    # Files that exist as HTML but don't have corresponding data files
    html_without_data = html_files - data_files
    
    # Combine and deduplicate
    orphaned = orphaned_html.union(html_without_data)
    
    return orphaned

def cleanup_orphaned_files(orphaned_files, dry_run=True):
    """Remove orphaned files."""
    cna_dir = Path("web/cna")
    removed_count = 0
    
    print(f"\n{'DRY RUN: ' if dry_run else ''}Found {len(orphaned_files)} orphaned files:")
    
    for filename in sorted(orphaned_files):
        html_file = cna_dir / f"{filename}.html"
        
        if html_file.exists():
            print(f"  - {html_file}")
            if not dry_run:
                try:
                    html_file.unlink()
                    removed_count += 1
                    print(f"    ✓ Removed")
                except Exception as e:
                    print(f"    ✗ Error removing: {e}")
        else:
            print(f"  - {filename}.html (file not found)")
    
    if dry_run:
        print(f"\nDry run complete. {len(orphaned_files)} files would be removed.")
        print("Run with --execute to actually delete the files.")
    else:
        print(f"\nCleanup complete. Removed {removed_count} files.")

def main():
    """Main cleanup function."""
    # Check if we're in the right directory
    if not Path("web").exists():
        print("Error: This script must be run from the CNAScoreCard root directory.")
        sys.exit(1)
    
    # Parse command line arguments
    dry_run = True
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        dry_run = False
    
    print("CNA Files Cleanup Script")
    print("=" * 50)
    
    # Load current CNA data
    print("Loading current CNA data...")
    cna_data = load_cna_data()
    if not cna_data:
        sys.exit(1)
    
    # Get valid CNA names
    valid_names = get_valid_cna_names(cna_data)
    print(f"Found {len(valid_names)} valid CNAs in data")
    
    # Get existing files
    html_files = get_existing_html_files()
    data_files = get_existing_data_files()
    
    print(f"Found {len(html_files)} HTML files in web/cna/")
    print(f"Found {len(data_files)} data files in web/cna/data/")
    
    # Find orphaned files
    orphaned = find_orphaned_files(valid_names, html_files, data_files)
    
    if not orphaned:
        print("\n✓ No orphaned files found. All HTML files have corresponding data.")
        return
    
    # Show detailed analysis
    print(f"\nAnalysis:")
    print(f"  Valid CNA names: {len(valid_names)}")
    print(f"  HTML files: {len(html_files)}")
    print(f"  Data files: {len(data_files)}")
    print(f"  Orphaned files: {len(orphaned)}")
    
    # Cleanup orphaned files
    cleanup_orphaned_files(orphaned, dry_run)
    
    # Show some examples of valid vs orphaned
    if orphaned:
        print(f"\nExample valid files:")
        valid_examples = list(valid_names.intersection(html_files))[:5]
        for example in valid_examples:
            print(f"  ✓ {example}.html")
        
        print(f"\nExample orphaned files:")
        for example in list(orphaned)[:5]:
            print(f"  ✗ {example}.html")

if __name__ == "__main__":
    main()