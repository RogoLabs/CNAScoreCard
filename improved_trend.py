"""
improved_trend.py: Enhanced trend calculation for CNA Scorecard pipeline.

Improvements over the original trend.py:
1. Treats months with no CVEs as NULL (None in Python) rather than 0.0
2. Uses a lower threshold (2.5 points instead of 5) for detecting significant trend changes
3. Provides more descriptive trend messages based on activity patterns
4. Compares periods with actual data for more accurate trend analysis
"""
from typing import List, Dict, Tuple, Optional
from datetime import datetime
from collections import defaultdict

def calculate_monthly_trend(scored_cves: List[Dict], months: int = 6) -> List[Optional[float]]:
    """
    Given a CNA's scored CVEs, returns an array of average scores for each of the last `months` months.
    Months with no CVEs will be None (NULL) rather than 0.0 or carried forward values.
    """
    import calendar
    
    # Build month buckets for last `months` months
    today = datetime.utcnow().date()
    buckets = []
    for i in range(months-1, -1, -1):
        month = (today.month - i - 1) % 12 + 1
        year = today.year - ((today.month - i - 1) // 12)
        buckets.append((year, month))

    # Group scores by bucket
    month_scores = defaultdict(list)
    for cve in scored_cves:
        dp = cve.get('datePublished', '')
        try:
            dt = datetime.fromisoformat(dp.replace('Z', '+00:00')).date() if 'T' in dp else datetime.strptime(dp, '%Y-%m-%d').date()
            bucket = (dt.year, dt.month)
            if bucket in buckets:
                score = cve.get('totalCveScore') or cve.get('totalScore', 0)
                month_scores[bucket].append(score)
        except Exception:
            continue
            
    # Compute averages, using None for months with no data
    avgs = []
    
    for bucket in buckets:
        scores = month_scores.get(bucket, [])
        if scores:
            # If we have scores this month, calculate the average
            avg = round(sum(scores) / len(scores), 2)
        else:
            # If no scores this month, use None (NULL)
            avg = None
            
        avgs.append(avg)
        
    return avgs

def summarize_trend(monthly_trends: List[Optional[float]]) -> Dict[str, str]:
    """
    Returns trend_direction and trend_description based on monthly_trends array.
    Uses a lower threshold (2.5 points instead of 5) and more descriptive messages.
    Handles missing values properly (months with no CVEs are dropped).
    Prioritizes score improvement patterns over just recent activity.
    """
    if not monthly_trends or len(monthly_trends) < 2:
        return {'trend_direction': 'N/A', 'trend_description': 'Insufficient data'}
    
    # Filter out None values for analysis (0.0 values should already be removed)
    valid_trends = [t for t in monthly_trends if t is not None]
    
    if not valid_trends:
        return {'trend_direction': 'steady', 'trend_description': '➡️ No activity'}
    
    # Check if all valid values are the same
    if len(set(valid_trends)) == 1:
        return {'trend_direction': 'steady', 'trend_description': f'➡️ Stable at {valid_trends[0]:.1f}%'}
    
    # Find most recent two valid data points for recent trend
    recent_values = [t for t in reversed(monthly_trends) if t is not None]
    if len(recent_values) >= 2:
        recent_delta = recent_values[0] - recent_values[1]  # newest minus second newest
    else:
        recent_delta = 0
    
    # Split valid trends into first and second half for period comparison
    valid_count = len(valid_trends)
    if valid_count >= 4:
        half = valid_count // 2
        first_half = valid_trends[:half]
        second_half = valid_trends[half:]
        
        first_half_avg = sum(first_half) / len(first_half)
        second_half_avg = sum(second_half) / len(second_half)
        period_delta = second_half_avg - first_half_avg
    else:
        # Not enough data points for reliable period comparison
        period_delta = 0
        first_half_avg = 0
        second_half_avg = sum(valid_trends) / len(valid_trends) if valid_trends else 0
    
    # Count active months (valid scores)
    active_months = len(valid_trends)
    
    # We need to focus on the trend between actual data points, not on the presence/absence of data
    # Find the first and last valid scores to determine overall trend direction
    valid_indices = [i for i, t in enumerate(monthly_trends) if t is not None]
    
    # Only check for recent activity/inactivity if it makes sense in context
    recent_activity = False
    recent_inactivity = False
    
    if valid_indices and valid_indices[-1] == len(monthly_trends) - 1:
        # The most recent month has data - possible recent activity
        if len(valid_indices) == 1 or valid_indices[-2] != valid_indices[-1] - 1:
            recent_activity = True
    
    # We'll only consider recent inactivity if it follows a steady pattern of activity
    # If there's an overall improvement despite ending with NULL, we shouldn't call it "declining"
    
    # For sparse data, look at first and last valid data points to determine overall trend
    if len(valid_indices) >= 2:
        first_valid = valid_indices[0]
        last_valid = valid_indices[-1]
        first_score = monthly_trends[first_valid]
        last_score = monthly_trends[last_valid]
        overall_delta = last_score - first_score
    else:
        overall_delta = 0
    
    # Check for improvement in recent scores
    last_valid_scores = valid_trends[-2:] if len(valid_trends) >= 2 else valid_trends
    most_recent_improvement = round(last_valid_scores[-1] - last_valid_scores[0], 2) if len(last_valid_scores) >= 2 else 0
    
    # Round overall_delta for accuracy
    if len(valid_indices) >= 2:
        overall_delta = round(overall_delta, 2)
    
    # Determine trend based on data patterns
    if overall_delta > 2.0:  # If there's an overall improvement between first and last valid data
        return {'trend_direction': 'improving', 'trend_description': f'↗️ Up {abs(overall_delta):.1f} pts'}
    elif most_recent_improvement > 2.0:  # Specific check for recent improvement like ProgressSoftware
        return {'trend_direction': 'improving', 'trend_description': f'↗️ Up {abs(most_recent_improvement):.1f} pts'}
    elif recent_activity:
        return {'trend_direction': 'improving', 'trend_description': f'↗️ Score: {valid_trends[-1]:.1f}%'}
    elif overall_delta < -2.0:  # If there's an overall decline between first and last valid data
        return {'trend_direction': 'declining', 'trend_description': f'↘️ Down {abs(overall_delta):.1f} pts'}
    elif most_recent_improvement < -2.0:  # Check for recent decline
        return {'trend_direction': 'declining', 'trend_description': f'↘️ Down {abs(most_recent_improvement):.1f} pts'}
    elif recent_delta > 2.5 or period_delta > 2.0:  # Additional checks for trends using other metrics
        delta = max(abs(recent_delta), abs(period_delta))
        return {'trend_direction': 'improving', 'trend_description': f'↗️ Up {round(delta, 1):.1f} pts'}
    elif recent_delta < -2.5 or period_delta < -2.0:  # Additional checks for trends using other metrics
        delta = max(abs(recent_delta), abs(period_delta))
        return {'trend_direction': 'declining', 'trend_description': f'↘️ Down {round(delta, 1):.1f} pts'}
    else:
        if active_months <= 1:
            # Only one valid data point
            month_index = next((i for i, t in enumerate(monthly_trends) if t is not None), -1)
            if month_index < len(monthly_trends) // 2:
                return {'trend_direction': 'declining', 'trend_description': f'↘️ Early data only'}
            else:
                return {'trend_direction': 'improving', 'trend_description': f'↗️ New activity'}
        else:
            return {'trend_direction': 'steady', 'trend_description': f'➡️ Stable at {second_half_avg:.1f}%'}


def test_with_sample_data():
    """Test the improved trend calculation with sample data patterns"""
    test_cases = [
        # All None case (no activity)
        {"name": "No Activity", "trends": [None, None, None, None, None, None]},
        
        # Alternating pattern (ZUSO ART case)
        {"name": "Alternating", "trends": [None, None, 80.0, None, 80.0, None]},
        
        # Sporadic activity
        {"name": "Single Activity", "trends": [None, None, None, None, 80.0, None]},
        
        # Stable case
        {"name": "Stable", "trends": [80.0, 80.0, 80.0, 80.0, 80.0, 80.0]},
        
        # Clear improvement
        {"name": "Improving", "trends": [75.0, 75.0, 76.0, 78.0, 79.0, 81.0]},
        
        # Clear decline
        {"name": "Declining", "trends": [82.0, 81.0, 79.0, 78.0, 77.0, 75.0]},
        
        # Recently active case
        {"name": "Recent Activity", "trends": [None, None, None, None, None, 80.0]},
        
        # Recently inactive case
        {"name": "Recent Inactivity", "trends": [75.0, 78.0, 80.0, 82.0, 85.0, None]},
        
        # Sparse data case
        {"name": "Sparse Data", "trends": [None, 78.0, None, None, 82.0, None]},
    ]
    
    print("Testing improved trend calculation with sample data:")
    print("=" * 60)
    
    for case in test_cases:
        result = summarize_trend(case["trends"])
        print(f"\nCase: {case['name']}")
        print(f"Monthly Trends: {case['trends']}")
        print(f"Direction: {result['trend_direction']}")
        print(f"Description: {result['trend_description']}")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    test_with_sample_data()
