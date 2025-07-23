"""
simplified_trend.py: Simplified trend calculation for CNA Scorecard pipeline.

This implementation only compares the last 2 different non-null values to determine trend direction.
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
    Uses a simplified approach that only compares the last 2 different non-null values.
    
    Examples:
    [80, 0, 0, 0, 65, 80] → Improvement of 15 (comparing 65 and 80)
    [80, 0, 0, 65, 0, 80] → Improvement of 15 (comparing 65 and 80)
    [0, 0, 0, 0, 0, 0] → Steady (no valid comparison)
    [70, 70, 70, 70, 70, 70] → Steady (no change between values)
    [80, 0, 0, 0, 65, 0] → Decrease of 15 (comparing 65 and 0)
    [80, 0, 0, 80, 65, 0] → Decrease of 65 (comparing 65 and 0)
    """
    # If no monthly_trends data, return N/A
    if not monthly_trends:
        return {'trend_direction': 'N/A', 'trend_description': 'Insufficient data'}
    
    # Filter out None values to get only valid scores
    valid_values = [v for v in monthly_trends if v is not None]
    
    # If no valid values, return N/A
    if not valid_values:
        return {'trend_direction': 'N/A', 'trend_description': '❌ No data'}
    
    # If only one valid value, can't determine a trend
    if len(valid_values) == 1:
        return {'trend_direction': 'steady', 'trend_description': f'➡️ Stable at {valid_values[0]:.1f}%'}
    
    # Get the last valid value (most recent)
    last_value = valid_values[-1]
    
    # Find the previous different value (scanning from right to left)
    # Start from the second-to-last value and go left until finding a different value
    prev_value = None
    for i in range(len(valid_values)-2, -1, -1):
        if valid_values[i] != last_value:
            prev_value = valid_values[i]
            break
    
    # If no different value found, all values are the same
    if prev_value is None:
        return {'trend_direction': 'steady', 'trend_description': f'➡️ Stable at {last_value:.1f}%'}
    
    # Calculate the difference between last value and previous different value
    diff = round(last_value - prev_value, 1)
    
    # Determine trend direction based on the difference
    if diff > 0:
        return {
            'trend_direction': 'improving',
            'trend_description': f'↗️ Up {abs(diff):.1f} pts'
        }
    elif diff < 0:
        return {
            'trend_direction': 'declining',
            'trend_description': f'↘️ Down {abs(diff):.1f} pts'
        }
    else:
        # This shouldn't happen given our logic, but just in case
        return {
            'trend_direction': 'steady',
            'trend_description': f'➡️ Stable at {last_value:.1f}%'
        }

def test_with_sample_data():
    """Test the simplified trend calculation with sample data patterns"""
    test_cases = [
        # User's examples
        {"name": "Improvement with recent data", "trends": [80.0, None, None, None, 65.0, 80.0]},
        {"name": "Improvement with gap", "trends": [80.0, None, None, 65.0, None, 80.0]},
        {"name": "All zeros", "trends": [0.0, 0.0, 0.0, 0.0, 0.0, 0.0]},
        {"name": "All same value", "trends": [70.0, 70.0, 70.0, 70.0, 70.0, 70.0]},
        {"name": "Decline with recent data", "trends": [80.0, None, None, None, 65.0, None]},
        {"name": "Decline with varying data", "trends": [80.0, None, None, 80.0, 65.0, None]},
        
        # Additional test cases
        {"name": "No data", "trends": [None, None, None, None, None, None]},
        {"name": "Single value", "trends": [None, None, None, None, None, 75.0]},
        {"name": "ProgressSoftware example", "trends": [80.0, 80.0, 80.0, 65.0, None, 80.0]},
        {"name": "GovTech CSG example", "trends": [85.0, 83.33, None, 80.0, 82.0, None]},
    ]
    
    print("Testing simplified trend calculation with sample data:")
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
