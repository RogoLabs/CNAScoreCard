#!/usr/bin/env python3

import json
import os
import glob
from pathlib import Path
from collections import defaultdict

def main():
    """
    Analyze CNA rankings based on overall_average_score to check if rankings are calculated correctly.
    Takes into account tie-breaking based on number of published CVEs.
    """
    print("Analyzing CNA rankings based on overall_average_score with CVE count tie-breaking...")
    
    # Path to the CNA JSON files
    cna_data_path = Path('/Users/gamblin/Documents/Github/CNAScoreCard/web/data/cna')
    
    # List to store CNA data for analysis
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
    sorted_cnas = sorted(cna_list, key=lambda x: (x['overall_average_score'], x['total_cves']), reverse=True)
    
    # Group CNAs by score to identify ties
    score_groups = defaultdict(list)
    for cna in sorted_cnas:
        score_groups[cna['overall_average_score']].append(cna)
    
    # Identify scores with ties
    tie_scores = [score for score, cnas in score_groups.items() if len(cnas) > 1]
    print(f"\nFound {len(tie_scores)} scores with ties")
    
    # Add calculated rank based on sorted position
    for i, cna in enumerate(sorted_cnas):
        # Rank is 1-based
        cna['calculated_rank'] = i + 1
        cna['rank_diff'] = cna['current_rank'] - cna['calculated_rank'] if cna['current_rank'] is not None else None
    
    # Print header for ties analysis
    if tie_scores:
        print("\nAnalyzing ties:")
        print("{:<8} {:<30} {:<15} {:<15} {:<15}".format(
            "Score", "CNA", "Total CVEs", "Recent CVEs", "Current Rank"
        ))
        print("=" * 85)
        
        # For each tie score, print details of CNAs with that score
        for score in tie_scores[:10]:  # Limit to first 10 tie scores to avoid too much output
            cnas_with_score = sorted(score_groups[score], key=lambda x: x['total_cves'], reverse=True)
            for cna in cnas_with_score:
                print("{:<8.2f} {:<30} {:<15} {:<15} {:<15}".format(
                    score,
                    cna['cna'][:30],
                    cna['total_cves'],
                    cna['recent_cves_count'],
                    str(cna['current_rank']) if cna['current_rank'] is not None else "None"
                ))
            print("-" * 85)
    
    # Print header for main analysis
    print("\n{:<30} {:<10} {:<15} {:<10} {:<10} {:<15} {:<10}".format(
        "CNA Name", "Score", "Current Rank", "Calc Rank", "Diff", "Total CVEs", "Percentile"
    ))
    print("=" * 100)
    
    # Print sorted list
    for cna in sorted_cnas:
        print("{:<30} {:<10.2f} {:<15} {:<10} {:<10} {:<15} {:<10}".format(
            cna['cna'][:30], 
            cna['overall_average_score'],
            str(cna['current_rank']) if cna['current_rank'] is not None else "None",
            cna['calculated_rank'],
            str(cna['rank_diff']) if cna['rank_diff'] is not None else "N/A",
            cna['total_cves'],
            str(cna['percentile']) if cna['percentile'] is not None else "None"
        ))
    
    # Count mismatches
    mismatches = [cna for cna in sorted_cnas if cna['rank_diff'] != 0 and cna['rank_diff'] is not None]
    print(f"\nFound {len(mismatches)} CNAs with ranking mismatches")
    
    # Check if percentile calculations match the ranks
    if sorted_cnas and sorted_cnas[0].get('active_cna_count'):
        total_cnas = sorted_cnas[0]['active_cna_count']
        print(f"\nAnalyzing percentiles based on active_cna_count of {total_cnas}:")
        for cna in sorted_cnas[:10]:  # Check first 10 as samples
            if cna['current_rank'] is not None and cna['percentile'] is not None:
                calculated_percentile = 100 * (1 - (cna['current_rank'] - 1) / total_cnas)
                percentile_diff = abs(calculated_percentile - cna['percentile'])
                print(f"{cna['cna'][:30]}: Stored percentile: {cna['percentile']:.1f}, Calculated: {calculated_percentile:.1f}, Diff: {percentile_diff:.1f}")
    
    # Save data to CSV for further analysis
    with open('cna_ranking_analysis.csv', 'w') as f:
        f.write("CNA,OverallAverageScore,CurrentRank,CalculatedRank,Difference,TotalCVEs,RecentCVEs,Percentile\n")
        for cna in sorted_cnas:
            f.write(f"{cna['cna']},{cna['overall_average_score']},{cna['current_rank'] or ''},{cna['calculated_rank']},{cna['rank_diff'] or ''},{cna['total_cves']},{cna['recent_cves_count']},{cna['percentile'] or ''}\n")
    
    print("\nAnalysis complete. Data saved to cna_ranking_analysis.csv")

if __name__ == "__main__":
    main()
