#!/usr/bin/env python
"""
Count trend directions across all CNA JSON files
"""
import os
import json
from collections import Counter, defaultdict

def analyze_cna_trends(json_dir):
    """Analyze trend directions and descriptions in all CNA JSON files"""
    trend_directions = Counter()
    trend_descriptions = Counter()
    cnas_by_trend = defaultdict(list)
    total_files = 0
    
    # Process each JSON file in the directory
    for filename in os.listdir(json_dir):
        if not filename.endswith('.json'):
            continue
            
        total_files += 1
        filepath = os.path.join(json_dir, filename)
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            # Extract CNA name and trend information
            cna_name = filename[:-5]  # Remove .json extension
            
            # Extract trend direction and description from the first scoring entry
            cna_scoring = data.get('cna_scoring', [])
            if cna_scoring:
                trend_direction = cna_scoring[0].get('trend_direction', 'unknown')
                trend_description = cna_scoring[0].get('trend_description', 'unknown')
                monthly_trends = cna_scoring[0].get('monthly_trends', [])
                
                # Count trend directions
                trend_directions[trend_direction] += 1
                trend_descriptions[trend_description] += 1
                
                # Track CNAs by trend direction
                cnas_by_trend[trend_direction].append({
                    'name': cna_name,
                    'description': trend_description,
                    'monthly_trends': monthly_trends
                })
                
        except Exception as e:
            print(f"Error processing {filename}: {e}")
    
    return {
        'total_files': total_files,
        'trend_directions': trend_directions,
        'trend_descriptions': trend_descriptions,
        'cnas_by_trend': cnas_by_trend
    }

def print_analysis(results):
    """Print analysis results in a readable format"""
    print("=" * 50)
    print(f"Analyzed {results['total_files']} CNA JSON files")
    print("=" * 50)
    
    print("\nTrend Direction Counts:")
    print("-" * 30)
    for direction, count in sorted(results['trend_directions'].items(), key=lambda x: x[1], reverse=True):
        percent = (count / results['total_files']) * 100
        print(f"{direction}: {count} ({percent:.1f}%)")
    
    print("\nSample CNAs by Trend Direction:")
    print("-" * 30)
    for direction, cnas in results['cnas_by_trend'].items():
        print(f"\n{direction.upper()} ({len(cnas)} CNAs):")
        # Show up to 5 examples for each trend
        for i, cna in enumerate(cnas[:5]):
            print(f"  {i+1}. {cna['name']} - {cna['description']}")
            print(f"     Monthly trends: {cna['monthly_trends']}")
        
        if len(cnas) > 5:
            print(f"  ... and {len(cnas) - 5} more")

if __name__ == "__main__":
    json_dir = "/Users/gamblin/Documents/Github/CNAScoreCard/web/data/cna"
    results = analyze_cna_trends(json_dir)
    print_analysis(results)
