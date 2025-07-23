#!/usr/bin/env python3
"""
Quick test to verify the trend calculation specifically for the ProgressSoftware case
"""

from improved_trend import summarize_trend

# ProgressSoftware monthly_trends from JSON
original_trends = [80.0, 80.0, 80.0, 65.0, 0.0, 80.0]

# Remove zeros as per updated approach
filtered_trends = [value for value in original_trends if value != 0.0]

# Calculate trend using our improved algorithm
result = summarize_trend(filtered_trends)

print("Original Trends:", original_trends)
print("Filtered Trends:", filtered_trends)
print("Trend Direction:", result['trend_direction'])
print("Trend Description:", result['trend_description'])
