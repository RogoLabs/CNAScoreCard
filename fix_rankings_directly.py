#!/usr/bin/env python3

import json
import os
import glob
from pathlib import Path
from collections import defaultdict

def main():
    """
    Directly fix CNA rankings by updating all JSON files with rankings 
    based on overall_average_score with tie-breaking by total_cves.
    """
    print("Fixing CNA rankings directly in JSON files...")
    
    # Path to the CNA JSON files
    cna_data_path = Path('/Users/gamblin/Documents/Github/CNAScoreCard/web/data/cna')
    
    # List to store CNA data for ranking calculation
    cna_list = []
    
    # Read all JSON files in the directory
    json_files = glob.glob(str(cna_data_path / '*.json'))
    print(f"Found {len(json_files)} CNA JSON files")
    
    # Process each JSON file to extract scoring information
    for json_file in json_files:
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Extract CNA name from filename or data
            cna_name = data.get('cna_info', {}).get('cna', os.path.basename(json_file).replace('.json', ''))
            
            # Extract the overall_average_score from the cna_scoring array
            overall_average_score = None
            total_cves = 0
            
            if 'cna_scoring' in data and isinstance(data['cna_scoring'], list) and len(data['cna_scoring']) > 0:
                scoring_data = data['cna_scoring'][0]
                overall_average_score = scoring_data.get('overall_average_score', 0)
                total_cves = scoring_data.get('total_cves', 0)
            
            # Store the data with the file path for later updates
            cna_list.append({
                'cna': cna_name,
                'overall_average_score': overall_average_score or 0,
                'total_cves': total_cves,
                'file_path': json_file,
                'data': data
            })
        except Exception as e:
            print(f"Error processing {json_file}: {str(e)}")
    
    print(f"Successfully processed {len(cna_list)} CNAs")
    
    # Sort CNAs by overall_average_score in descending order (higher is better)
    # For ties, sort by total_cves in descending order
    sorted_cnas = sorted(cna_list, key=lambda x: (x['overall_average_score'], x['total_cves']), reverse=True)
    
    # Calculate new rankings
    total_cnas = len(sorted_cnas)
    updated_files = 0
    
    print(f"\nUpdating rankings for {total_cnas} CNAs...")
    print(f"Top 5 CNAs by overall_average_score (with tie-breaking by total_cves):")
    
    # Update each CNA's ranking in their JSON file
    for idx, cna in enumerate(sorted_cnas):
        # Calculate new rank and percentile
        new_rank = idx + 1
        new_percentile = round(((total_cnas - idx) / total_cnas) * 100, 1)
        
        # Log top 5 CNAs
        if idx < 5:
            print(f"  Rank {new_rank}: {cna['cna']} - Score: {cna['overall_average_score']}, CVEs: {cna['total_cves']}")
        
        # Get the current data and check if it needs updating
        data = cna['data']
        current_rank = data.get('rank', 0)
        current_percentile = data.get('percentile', 0)
        
        # Check if this is ProgressSoftware or another key CNA for detailed logging
        is_key_cna = cna['cna'] in ["ProgressSoftware", "mitre", "debian", "Linux"]
        if is_key_cna:
            print(f"\nKey CNA: {cna['cna']}")
            print(f"  Before: Rank {current_rank}, Percentile {current_percentile}")
            print(f"  After:  Rank {new_rank}, Percentile {new_percentile}")
        
        # Update the ranking information
        data['rank'] = new_rank
        data['active_cna_count'] = total_cnas
        data['percentile'] = new_percentile
        
        # Write the updated data back to the file with verbose logging
        try:
            # Verify we have the correct data before writing
            print(f"Writing rank {new_rank} for {cna['cna']}" if is_key_cna else "", end="\r")
            
            # Use os module for better file access control
            file_path = cna['file_path']
            
            # Check file permissions
            if not os.access(file_path, os.W_OK):
                print(f"WARNING: No write permission for {file_path}")
            
            # Write with explicit flush and sync
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
                f.flush()  # Flush to OS buffer
                os.fsync(f.fileno())  # Force write to disk
            
            # Verify the write by reading the file back
            if is_key_cna:
                with open(file_path, 'r') as f:
                    verification_data = json.load(f)
                    verified_rank = verification_data.get('rank')
                    print(f"  Verified rank after write: {verified_rank}")
            
            updated_files += 1
        except Exception as e:
            print(f"Error writing to {cna['file_path']}: {str(e)}")
    
    print(f"\nSuccessfully updated {updated_files} CNA JSON files with new rankings")
    print("Run the verification script to confirm the changes.")

if __name__ == "__main__":
    main()
