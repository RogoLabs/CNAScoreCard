#!/usr/bin/env python3

import json
import os
import glob
from pathlib import Path
from collections import defaultdict

def main():
    """
    Verify that the CNA ranking is correctly based on overall_average_score
    with tie-breaking based on total_cves.
    """
    print("Verifying CNA ranking based on overall_average_score with CVE count tie-breaking...")
    
    # Path to the CNA JSON files
    cna_data_path = Path('/Users/gamblin/Documents/Github/CNAScoreCard/web/data/cna')
    
    # List to store CNA data for verification
    cna_list = []
    
    # Read all JSON files in the directory
    json_files = glob.glob(str(cna_data_path / '*.json'))
    print(f"Found {len(json_files)} CNA JSON files")
    
    # Process each JSON file
    for json_file in json_files:
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Extract CNA name from filename or data
            cna_name = data.get('cna_info', {}).get('cna', os.path.basename(json_file).replace('.json', ''))
            
            # Extract relevant ranking information
            current_rank = data.get('rank', None)
            active_cna_count = data.get('active_cna_count', None)
            percentile = data.get('percentile', None)
            
            # Extract the overall_average_score from the cna_scoring array
            overall_average_score = None
            total_cves = 0
            total_cves_scored = 0
            
            if 'cna_scoring' in data and isinstance(data['cna_scoring'], list) and len(data['cna_scoring']) > 0:
                scoring_data = data['cna_scoring'][0]
                overall_average_score = scoring_data.get('overall_average_score', None)
                total_cves = scoring_data.get('total_cves', 0)
                total_cves_scored = scoring_data.get('total_cves_scored', 0)
            
            # Get recent CVEs count
            recent_cves_count = len(data.get('recent_cves', []))
            
            # Store the data if we have an overall_average_score
            if overall_average_score is not None:
                cna_list.append({
                    'cna': cna_name,
                    'overall_average_score': overall_average_score,
                    'current_rank': current_rank,
                    'active_cna_count': active_cna_count,
                    'percentile': percentile,
                    'total_cves': total_cves,
                    'total_cves_scored': total_cves_scored,
                    'recent_cves_count': recent_cves_count
                })
        except Exception as e:
            print(f"Error processing {json_file}: {str(e)}")
    
    print(f"Successfully processed {len(cna_list)} CNAs with valid scores")
    
    # Sort CNAs by overall_average_score in descending order (higher is better)
    # For ties, sort by total_cves in descending order
    expected_cnas = sorted(cna_list, key=lambda x: (x['overall_average_score'], x['total_cves']), reverse=True)
    
    # Add expected rank based on sorted position
    for i, cna in enumerate(expected_cnas):
        # Rank is 1-based
        cna['expected_rank'] = i + 1
        cna['rank_diff'] = cna['current_rank'] - cna['expected_rank'] if cna['current_rank'] is not None else None
    
    # Group CNAs by score to identify ties
    score_groups = defaultdict(list)
    for cna in expected_cnas:
        score_groups[cna['overall_average_score']].append(cna)
    
    # Identify scores with ties
    tie_scores = [score for score, cnas in score_groups.items() if len(cnas) > 1]
    print(f"\nFound {len(tie_scores)} scores with ties")
    
    # Print header for ties analysis
    if tie_scores:
        print("\nAnalyzing ties:")
        print("{:<8} {:<30} {:<15} {:<15} {:<15} {:<15}".format(
            "Score", "CNA", "Total CVEs", "Current Rank", "Expected Rank", "Diff"
        ))
        print("=" * 100)
        
        # For each tie score, print details of CNAs with that score
        for score in tie_scores[:10]:  # Limit to first 10 tie scores to avoid too much output
            cnas_with_score = sorted(score_groups[score], key=lambda x: x['total_cves'], reverse=True)
            for cna in cnas_with_score:
                print("{:<8.2f} {:<30} {:<15} {:<15} {:<15} {:<15}".format(
                    score,
                    cna['cna'][:30],
                    cna['total_cves'],
                    str(cna['current_rank']) if cna['current_rank'] is not None else "None",
                    cna['expected_rank'],
                    str(cna['rank_diff']) if cna['rank_diff'] is not None else "N/A"
                ))
            print("-" * 100)
    
    # Print header for main analysis
    print("\n{:<30} {:<10} {:<15} {:<15} {:<10} {:<15} {:<10}".format(
        "CNA Name", "Score", "Current Rank", "Expected Rank", "Diff", "Total CVEs", "Percentile"
    ))
    print("=" * 105)
    
    # Print top and bottom 10 CNAs
    for cna in expected_cnas[:10]:  # Top 10
        print("{:<30} {:<10.2f} {:<15} {:<15} {:<10} {:<15} {:<10}".format(
            cna['cna'][:30], 
            cna['overall_average_score'],
            str(cna['current_rank']) if cna['current_rank'] is not None else "None",
            cna['expected_rank'],
            str(cna['rank_diff']) if cna['rank_diff'] is not None else "N/A",
            cna['total_cves'],
            str(cna['percentile']) if cna['percentile'] is not None else "None"
        ))
    
    print("\n... middle CNAs omitted for brevity ...\n")
    
    for cna in expected_cnas[-10:]:  # Bottom 10
        print("{:<30} {:<10.2f} {:<15} {:<15} {:<10} {:<15} {:<10}".format(
            cna['cna'][:30], 
            cna['overall_average_score'],
            str(cna['current_rank']) if cna['current_rank'] is not None else "None",
            cna['expected_rank'],
            str(cna['rank_diff']) if cna['rank_diff'] is not None else "N/A",
            cna['total_cves'],
            str(cna['percentile']) if cna['percentile'] is not None else "None"
        ))
    
    # Count mismatches
    mismatches = [cna for cna in expected_cnas if cna['rank_diff'] != 0 and cna['rank_diff'] is not None]
    print(f"\nFound {len(mismatches)} CNAs with ranking mismatches")
    
    # Check if the ranking follows our expected sorting
    if len(mismatches) == 0:
        print("\n✅ SUCCESS: All CNAs are correctly ranked based on overall_average_score with CVE count tie-breaking!")
    else:
        print("\n❌ ERROR: Some CNAs have incorrect rankings. Check the analysis for details.")
        
    # Save data to CSV for further analysis
    with open('ranking_verification.csv', 'w') as f:
        f.write("CNA,OverallAverageScore,CurrentRank,ExpectedRank,Difference,TotalCVEs,RecentCVEs,Percentile\n")
        for cna in expected_cnas:
            f.write(f"{cna['cna']},{cna['overall_average_score']},{cna['current_rank'] or ''},{cna['expected_rank']},{cna['rank_diff'] or ''},{cna['total_cves']},{cna['recent_cves_count']},{cna['percentile'] or ''}\n")
    
    print("\nVerification complete. Data saved to ranking_verification.csv")

if __name__ == "__main__":
    main()
