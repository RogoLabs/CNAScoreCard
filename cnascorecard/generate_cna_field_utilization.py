#!/usr/bin/env python3
"""
Script to generate CNA field utilization statistics for field-insights dashboard.
Outputs a JSON file with, for each field, the number of unique CNAs using it and the percentage of CNAs using it.
"""
import os
import json
from collections import defaultdict

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
COMPLETENESS_FILE = os.path.join(BASE_DIR, "output", "completeness_analysis_latest.json")
FIELD_INSIGHTS_DIR = os.path.join(BASE_DIR, "..", "web", "field-insights")
OUTPUT_FILE = os.path.join(FIELD_INSIGHTS_DIR, "cna_field_utilization.json")

# Load latest completeness analysis (fallback to most recent file if needed)
def get_latest_completeness_file():
    output_dir = os.path.join(BASE_DIR, "output")
    files = [f for f in os.listdir(output_dir) if f.startswith("completeness_analysis_") and f.endswith(".json")]
    if not files:
        raise FileNotFoundError("No completeness analysis files found.")
    files.sort(reverse=True)
    return os.path.join(output_dir, files[0])

def main():
    # Try to use a symlink or latest file
    try:
        path = COMPLETENESS_FILE if os.path.exists(COMPLETENESS_FILE) else get_latest_completeness_file()
    except Exception as e:
        print(f"Error: {e}")
        return
    with open(path, "r") as f:
        data = json.load(f)
    cna_stats = data.get("cna_stats", {})
    if not cna_stats:
        print("No CNA stats found in completeness analysis.")
        return
    # Build field->set(CNA) mapping
    field_to_cnas = defaultdict(set)
    for cna, stats in cna_stats.items():
        if cna == "Unknown":
            continue
        for field in stats:
            # Only count if the field is actually present for this CNA
            if stats[field].get("present", 0) > 0:
                field_to_cnas[field].add(cna)
    all_cnas = set(cna for cna in cna_stats if cna != "Unknown")
    total_cnas = len(all_cnas)
    # Build output
    output = []
    for field, cna_set in field_to_cnas.items():
        output.append({
            "field": field,
            "unique_cnas": len(cna_set),
            "cna_percent": 100.0 * len(cna_set) / total_cnas if total_cnas else 0.0
        })
    # Sort by percent descending
    output.sort(key=lambda x: x["cna_percent"], reverse=True)
    # Write output
    os.makedirs(FIELD_INSIGHTS_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Wrote CNA field utilization to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
