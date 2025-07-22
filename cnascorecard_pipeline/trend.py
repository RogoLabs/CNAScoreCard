"""
trend.py: Canonical month-by-month trend calculation for CNA Scorecard pipeline.
"""
from typing import List, Dict
from datetime import datetime

def calculate_monthly_trend(scored_cves: List[Dict], months: int = 6) -> List[float]:
    """
    Given a CNA's scored CVEs, returns an array of average scores for each of the last `months` months.
    """
    from datetime import datetime
    import calendar
    from collections import defaultdict

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
                month_scores[bucket].append(cve.get('totalScore', 0))
        except Exception:
            continue
    # Compute averages
    avgs = []
    for bucket in buckets:
        scores = month_scores.get(bucket, [])
        avg = round(sum(scores) / len(scores), 2) if scores else 0.0
        avgs.append(avg)
    return avgs

def summarize_trend(monthly_trends: List[float]) -> Dict[str, str]:
    """
    Returns trend_direction and trend_description based on monthly_trends array.
    """
    if not monthly_trends or len(monthly_trends) < 2:
        return {'trend_direction': 'N/A', 'trend_description': 'Insufficient data'}
    delta = monthly_trends[-1] - monthly_trends[-2]
    if delta > 5:
        return {'trend_direction': 'improving', 'trend_description': f'Score improved by {delta:.1f} points'}
    elif delta < -5:
        return {'trend_direction': 'declining', 'trend_description': f'Score declined by {abs(delta):.1f} points'}
    else:
        return {'trend_direction': 'steady', 'trend_description': f'Score stable at {monthly_trends[-1]:.1f}%'}
