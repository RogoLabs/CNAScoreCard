#!/usr/bin/env python
"""
Special test script for debugging trend calculation with ProgressSoftware data pattern
"""
from trend import summarize_trend

def debug_progress_software():
    """Debug the ProgressSoftware case specifically"""
    # Actual ProgressSoftware monthly trends
    progress_trends = [80.0, 80.0, 80.0, 65.0, None, 80.0]
    
    # Adding debug prints to trace execution
    print("\nDebugging ProgressSoftware trend calculation:")
    print("=" * 60)
    print(f"Input monthly_trends: {progress_trends}")
    
    # Filter out None values for analysis
    valid_trends = [t for t in progress_trends if t is not None]
    print(f"valid_trends: {valid_trends}")
    
    # Find most recent two valid data points for recent trend
    recent_values = [t for t in reversed(progress_trends) if t is not None]
    print(f"recent_values (reversed valid): {recent_values}")
    
    if len(recent_values) >= 2:
        recent_delta = recent_values[0] - recent_values[1]  # newest minus second newest
        print(f"recent_delta: {recent_delta}")
    else:
        recent_delta = 0
    
    # Calculate valid indices for overall delta
    valid_indices = [i for i, t in enumerate(progress_trends) if t is not None]
    print(f"valid_indices: {valid_indices}")
    
    if len(valid_indices) >= 2:
        first_valid = valid_indices[0]
        last_valid = valid_indices[-1]
        print(f"first_valid: {first_valid}, last_valid: {last_valid}")
        first_score = progress_trends[first_valid]
        last_score = progress_trends[last_valid]
        print(f"first_score: {first_score}, last_score: {last_score}")
        overall_delta = last_score - first_score
        print(f"overall_delta: {overall_delta}")
    else:
        overall_delta = 0
    
    # Check for improvement in recent scores
    last_valid_scores = valid_trends[-2:] if len(valid_trends) >= 2 else valid_trends
    print(f"last_valid_scores: {last_valid_scores}")
    most_recent_improvement = round(last_valid_scores[-1] - last_valid_scores[0], 2) if len(last_valid_scores) >= 2 else 0
    print(f"most_recent_improvement: {most_recent_improvement}")
    
    # Get actual summarize_trend result
    result = summarize_trend(progress_trends)
    print("\nActual summarize_trend result:")
    print(f"Direction: {result['trend_direction']}")
    print(f"Description: {result['trend_description']}")

if __name__ == "__main__":
    debug_progress_software()
