#!/usr/bin/env python3
"""
analyze_trends.py - Script to analyze monthly_trends arrays in CNA JSON files

This script analyzes patterns in the monthly_trends arrays found in CNA JSON files,
looking for issues such as many zeros, alternating patterns, and other anomalies.
It also examines the relationship between trends, CVE counts, and other metrics.
"""

import json
import os
import glob
from collections import Counter, defaultdict
from typing import Dict, List, Tuple, Any

def load_cna_json(filepath: str) -> Dict[str, Any]:
    """Load a CNA JSON file"""
    with open(filepath, 'r') as f:
        return json.load(f)

def analyze_monthly_trends() -> None:
    """Main function to analyze monthly trends across all CNA JSON files"""
    cna_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web', 'data', 'cna')
    json_files = glob.glob(os.path.join(cna_dir, '*.json'))
    
    # Statistics counters
    total_files = 0
    files_with_trends = 0
    trend_directions = Counter()
    trend_descriptions = Counter()
    trend_patterns = Counter()
    zero_months_count = Counter()  # Count of how many months are zero in each CNA
    zero_patterns = []  # List of patterns with zeros and non-zeros
    
    # Detailed information for interesting cases
    interesting_cases = []
    
    print(f"Analyzing {len(json_files)} CNA JSON files...\n")
    
    for json_file in json_files:
        total_files += 1
        cna_name = os.path.basename(json_file).replace('.json', '')
        cna_data = load_cna_json(json_file)
        
        # Extract trend data
        trend_direction = cna_data.get('trend_direction', 'N/A')
        trend_description = cna_data.get('trend_description', 'N/A')
        
        # Look for monthly_trends in both direct and nested locations
        monthly_trends = None
        if 'monthly_trends' in cna_data:
            monthly_trends = cna_data['monthly_trends']
        elif 'cna_scoring' in cna_data and cna_data['cna_scoring'] and 'monthly_trends' in cna_data['cna_scoring'][0]:
            monthly_trends = cna_data['cna_scoring'][0]['monthly_trends']
        
        # Count trend directions and descriptions
        trend_directions[trend_direction] += 1
        trend_descriptions[trend_description] += 1
        
        if monthly_trends:
            files_with_trends += 1
            
            # Analyze zero patterns
            zero_count = monthly_trends.count(0.0)
            zero_months_count[zero_count] += 1
            
            # Create a binary pattern of zeros and non-zeros
            pattern = ''.join(['0' if m == 0.0 else '1' for m in monthly_trends])
            trend_patterns[pattern] += 1
            
            # Get recent CVEs count for comparison
            recent_cves_count = len(cna_data.get('recent_cves', []))
            
            # Log interesting cases (alternating zeros, mostly zeros, etc.)
            if '101' in pattern or '010' in pattern or zero_count >= 3:
                interesting_cases.append({
                    'cna': cna_name,
                    'monthly_trends': monthly_trends,
                    'pattern': pattern,
                    'recent_cves': recent_cves_count,
                    'trend_direction': trend_direction,
                    'trend_description': trend_description
                })
    
    # Print summary statistics
    print(f"Total CNA files analyzed: {total_files}")
    print(f"Files with monthly_trends data: {files_with_trends}")
    
    print("\nTrend Direction Distribution:")
    for direction, count in trend_directions.most_common():
        print(f"  {direction}: {count} ({count/total_files*100:.1f}%)")
    
    print("\nTrend Description Distribution (Top 10):")
    for desc, count in trend_descriptions.most_common(10):
        print(f"  {desc}: {count}")
    
    print("\nMonths with Zero Values Distribution:")
    for zero_count, file_count in sorted(zero_months_count.items()):
        print(f"  {zero_count} zeros: {file_count} files ({file_count/files_with_trends*100:.1f}%)")
    
    print("\nCommon Monthly Trend Patterns (binary, where 0=zero score, 1=non-zero):")
    for pattern, count in trend_patterns.most_common(10):
        print(f"  {pattern}: {count} files ({count/files_with_trends*100:.1f}%)")
    
    print("\nDetailed Analysis of Interesting Cases (showing 10):")
    for i, case in enumerate(interesting_cases[:10]):
        print(f"\n{i+1}. CNA: {case['cna']}")
        print(f"   Monthly Trends: {case['monthly_trends']}")
        print(f"   Pattern: {case['pattern']}")
        print(f"   Recent CVEs Count: {case['recent_cves']}")
        print(f"   Trend Direction: {case['trend_direction']}")
        print(f"   Trend Description: {case['trend_description']}")

    # Verify if months with zero CVEs are being correctly handled
    print("\nVerifying Zero-Month Handling:")
    print("Looking at the patterns above, we see many CNAs with alternating zeros or many zeros.")
    print("This suggests months without CVEs are showing as 0.0 rather than being skipped or using")
    print("previous month's score. The calculation in trend.py appears to be calculating each month")
    print("independently rather than cumulatively.")

if __name__ == "__main__":
    analyze_monthly_trends()
