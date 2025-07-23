#!/usr/bin/env python3
"""
update_cna_trends.py - Script to update CNA JSON files with improved trend calculations

This script:
1. Loads all CNA JSON files
2. Applies the improved trend calculation algorithm from improved_trend.py
3. Updates the trend_direction, trend_description, and preserves the existing monthly_trends
4. Creates backup of original files
5. Writes updated JSON files back to disk

Usage:
    python update_cna_trends.py [--dry-run]
    
    --dry-run: Optional. Show what would be updated without making changes.
"""

import json
import os
import glob
import shutil
import argparse
from datetime import datetime
from typing import Dict, List, Any, Tuple
from improved_trend import summarize_trend

def backup_file(file_path: str) -> str:
    """Create a backup of a file with timestamp in name"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = f"{file_path}.{timestamp}.bak"
    shutil.copy2(file_path, backup_path)
    return backup_path

def process_cna_file(file_path: str, dry_run: bool = False) -> Dict[str, Any]:
    """Process a single CNA JSON file and update its trend data"""
    # Load the CNA data
    with open(file_path, 'r') as f:
        cna_data = json.load(f)
    
    cna_name = os.path.basename(file_path).replace('.json', '')
    original_trend = None
    new_trend = None
    
    # Check if monthly_trends exists and where
    monthly_trends = None
    if 'cna_scoring' in cna_data and cna_data['cna_scoring'] and 'monthly_trends' in cna_data['cna_scoring'][0]:
        # Extract existing monthly trends
        monthly_trends = cna_data['cna_scoring'][0].get('monthly_trends', [])
        if monthly_trends:
            # Save original trend info
            original_trend = {
                'direction': cna_data.get('trend_direction', 'N/A'),
                'description': cna_data.get('trend_description', 'N/A'),
                'monthly_trends': monthly_trends
            }
            
            # Completely drop 0.0 values from arrays for clarity
            processed_trends = [value for value in monthly_trends if value != 0.0]
            
            # Calculate new trend info
            new_trend_info = summarize_trend(processed_trends)
            new_trend = {
                'direction': new_trend_info['trend_direction'],
                'description': new_trend_info['trend_description'],
                'monthly_trends': monthly_trends  # Preserve original monthly_trends data format in JSON
            }
            
            # Update trend info in CNA data
            # Update both top-level and nested trend info to ensure consistency
            cna_data['trend_direction'] = new_trend_info['trend_direction']
            cna_data['trend_description'] = new_trend_info['trend_description']
            
            if 'cna_scoring' in cna_data and cna_data['cna_scoring']:
                cna_data['cna_scoring'][0]['trend_direction'] = new_trend_info['trend_direction']
                cna_data['cna_scoring'][0]['trend_description'] = new_trend_info['trend_description']
    
    if not dry_run and new_trend:
        # Create backup
        backup_path = backup_file(file_path)
        
        # Write updated file
        with open(file_path, 'w') as f:
            json.dump(cna_data, f, indent=2)
    
    return {
        'cna': cna_name,
        'updated': new_trend is not None,
        'original': original_trend,
        'new': new_trend
    }

def main():
    """Main function to update all CNA JSON files"""
    parser = argparse.ArgumentParser(description='Update CNA JSON files with improved trend calculations')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be updated without making changes')
    args = parser.parse_args()
    
    cna_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web', 'data', 'cna')
    json_files = glob.glob(os.path.join(cna_dir, '*.json'))
    
    print(f"{'DRY RUN: ' if args.dry_run else ''}Processing {len(json_files)} CNA JSON files...")
    
    # Counters
    total_processed = 0
    total_updated = 0
    total_unchanged = 0
    trend_changes = {'steady': 0, 'improving': 0, 'declining': 0, 'N/A': 0}
    
    # Track changes for reporting
    significant_changes = []
    
    # Process all files
    for json_file in json_files:
        result = process_cna_file(json_file, args.dry_run)
        total_processed += 1
        
        if result['updated']:
            total_updated += 1
            if result['original']['direction'] != result['new']['direction']:
                # Track trend direction changes
                trend_changes[result['new']['direction']] += 1
                
                # Record significant changes for reporting
                if result['original']['direction'] != 'N/A':  # Ignore N/A to meaningful changes
                    significant_changes.append({
                        'cna': result['cna'],
                        'from_direction': result['original']['direction'],
                        'to_direction': result['new']['direction'],
                        'from_desc': result['original']['description'],
                        'to_desc': result['new']['description'],
                        'monthly_trends': result['original']['monthly_trends']
                    })
        else:
            total_unchanged += 1
    
    # Print summary
    print(f"\nSummary of {'potential ' if args.dry_run else ''}changes:")
    print(f"Total files processed: {total_processed}")
    print(f"Files updated: {total_updated}")
    print(f"Files unchanged: {total_unchanged}")
    
    print("\nTrend direction changes:")
    for direction, count in trend_changes.items():
        print(f"  {direction}: {count}")
    
    print("\nSignificant trend direction changes (showing up to 10):")
    for i, change in enumerate(significant_changes[:10]):
        print(f"\n{i+1}. CNA: {change['cna']}")
        print(f"   Monthly Trends: {change['monthly_trends']}")
        print(f"   FROM: {change['from_direction']} - {change['from_desc']}")
        print(f"   TO: {change['to_direction']} - {change['to_desc']}")
    
    if args.dry_run:
        print("\nDRY RUN COMPLETE. No files were modified.")
        print("To apply these changes, run the script without the --dry-run flag.")
    else:
        print("\nUpdate complete. Original files were backed up with timestamp in the filename.")

if __name__ == "__main__":
    main()
