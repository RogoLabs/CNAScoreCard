"""
trends.py: Calculate and track performance trends for CNA Scorecard dashboard.

This module processes CVE data to generate daily performance trends and identify
top-improving CNAs over time for the Performance Trends dashboard.
"""
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from config import ScoringConfig
from utils import format_date_string
from scoring import score_cve_record

logger = logging.getLogger('cnascorecard.trends')
config = ScoringConfig()

def calculate_daily_trends(cve_records: List[Dict[str, Any]], 
                          output_dir: Path,
                          analysis_days: int = 180) -> Dict[str, Any]:
    """
    Calculate daily performance trends for the last N days.
    
    Args:
        cve_records: List of CVE records to analyze
        output_dir: Directory to save trends data
        analysis_days: Number of days to analyze (default: 180 = ~6 months)
        
    Returns:
        Dictionary containing trends data
    """
    logger.info(f"Calculating daily trends for last {analysis_days} days...")
    
    # Calculate date range (ensure timezone-aware for comparison)
    end_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=None)
    start_date = end_date - timedelta(days=analysis_days)
    
    # Group CVEs by publication date
    daily_cves = defaultdict(list)
    
    logger.info(f"Processing {len(cve_records)} CVE records for trends analysis")
    logger.info(f"Analysis window: {start_date} to {end_date}")
    
    parsed_count = 0
    valid_date_count = 0
    in_window_count = 0
    
    for cve in cve_records:
        try:
            # Extract publication date
            date_published = cve.get('cveMetadata', {}).get('datePublished', '')
            if not date_published:
                continue
                
            parsed_count += 1
            
            # Parse date (handle various formats) and make timezone-naive for comparison
            pub_date = datetime.fromisoformat(date_published.replace('Z', '+00:00'))
            pub_date = pub_date.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=None)
            
            valid_date_count += 1
            
            # Debug first few dates
            if valid_date_count <= 5:
                logger.info(f"Sample CVE date: {date_published} -> parsed: {pub_date}")
            
            # Only include CVEs within our analysis window
            if start_date <= pub_date <= end_date:
                daily_cves[pub_date.strftime('%Y-%m-%d')].append(cve)
                in_window_count += 1
                
        except (ValueError, TypeError) as e:
            logger.debug(f"Skipping CVE with invalid date: {e}")
            continue
    
    logger.info(f"Trends analysis stats: {parsed_count} had dates, {valid_date_count} parsed successfully, {in_window_count} within analysis window")
    
    logger.info(f"Found CVEs across {len(daily_cves)} days")
    
    # Calculate daily averages for each category
    daily_trends = {}
    
    current_date = start_date
    while current_date <= end_date:
        date_str = current_date.strftime('%Y-%m-%d')
        
        if date_str in daily_cves:
            day_scores = _calculate_daily_category_averages(daily_cves[date_str])
        else:
            # No CVEs on this date - use None values
            day_scores = {
                'root_cause_analysis': None,
                'severity_and_impact': None, 
                'software_identification': None,
                'patch_information': None,
                'total_cves': 0
            }
        
        daily_trends[date_str] = day_scores
        current_date += timedelta(days=1)
    
    # Calculate 7-day rolling averages
    rolling_trends = _calculate_rolling_averages(daily_trends, window_days=7)
    
    # Save trends data
    trends_data = {
        'daily_trends': daily_trends,
        'rolling_trends': rolling_trends,
        'analysis_period': {
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'total_days': analysis_days
        },
        'generated_at': datetime.now().isoformat()
    }
    
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / 'performance_trends.json'
    with open(output_file, 'w') as f:
        json.dump(trends_data, f, indent=2)
    
    logger.info(f"Generated trends data: {output_file}")
    return trends_data

def calculate_top_improvers(cve_records: List[Dict[str, Any]], 
                           output_dir: Path,
                           top_n: int = 10) -> List[Dict[str, Any]]:
    """
    Identify CNAs with the most improvement over the analysis period.
    
    Args:
        cve_records: List of CVE records to analyze
        output_dir: Directory to save improvers data  
        top_n: Number of top improvers to return
        
    Returns:
        List of top improving CNAs with improvement metrics
    """
    logger.info("Calculating top improving CNAs...")
    
    # Group CVEs by CNA and date
    cna_daily_scores = defaultdict(lambda: defaultdict(list))
    
    for cve in cve_records:
        try:
            # Score the CVE
            scored_cve = score_cve_record(cve)
            if not scored_cve:
                continue
                
            cna_name = scored_cve.get('assigningCna', 'Unknown')
            if cna_name == 'Unknown':
                continue
                
            date_published = scored_cve.get('datePublished', '')
            if not date_published:
                continue
                
            # Parse date
            pub_date = datetime.fromisoformat(date_published.replace('Z', '+00:00'))
            date_str = pub_date.strftime('%Y-%m-%d')
            
            # Store scores by CNA and date
            cna_daily_scores[cna_name][date_str].append(scored_cve['scoreBreakdown'])
            
        except (ValueError, TypeError) as e:
            logger.debug(f"Skipping CVE in improvers analysis: {e}")
            continue
    
    # Calculate improvement for each CNA
    improvements = []
    
    for cna_name, daily_data in cna_daily_scores.items():
        if len(daily_data) < 2:  # Need at least 2 data points
            continue
            
        # Get sorted dates
        sorted_dates = sorted(daily_data.keys())
        
        # Calculate averages for first and last periods (using 7-day windows)
        first_period_scores = _get_period_average_scores(daily_data, sorted_dates[:7])
        last_period_scores = _get_period_average_scores(daily_data, sorted_dates[-7:])
        
        if not first_period_scores or not last_period_scores:
            continue
            
        # Calculate improvement in each category
        category_improvements = {}
        total_improvement = 0
        
        for category in ['root_cause_analysis', 'severity_and_impact', 
                        'software_identification', 'patch_information']:
            first_avg = first_period_scores.get(category, 0)
            last_avg = last_period_scores.get(category, 0)
            improvement = last_avg - first_avg
            
            category_improvements[category] = {
                'first_period': first_avg,
                'last_period': last_avg, 
                'improvement': improvement
            }
            total_improvement += improvement
        
        # Only include CNAs with meaningful data volume
        total_cves = sum(len(scores) for scores in daily_data.values())
        if total_cves >= 5:  # Minimum threshold
            improvements.append({
                'cna_name': cna_name,
                'total_improvement': total_improvement,
                'category_improvements': category_improvements,
                'total_cves_analyzed': total_cves,
                'analysis_days': len(sorted_dates)
            })
    
    # Sort by total improvement (descending)
    improvements.sort(key=lambda x: x['total_improvement'], reverse=True)
    top_improvers = improvements[:top_n]
    
    # Save improvers data
    improvers_data = {
        'top_improvers': top_improvers,
        'generated_at': datetime.now().isoformat(),
        'analysis_criteria': {
            'minimum_cves': 5,
            'top_n_count': top_n
        }
    }
    
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / 'top_improvers.json'
    with open(output_file, 'w') as f:
        json.dump(improvers_data, f, indent=2)
    
    logger.info(f"Generated top improvers data: {output_file}")
    return top_improvers

def _calculate_daily_category_averages(day_cves: List[Dict[str, Any]]) -> Dict[str, float]:
    """Calculate average scores for each category for a single day's CVEs."""
    if not day_cves:
        return {
            'root_cause_analysis': None,
            'severity_and_impact': None,
            'software_identification': None, 
            'patch_information': None,
            'total_cves': 0
        }
    
    # Score all CVEs for this day
    scored_cves = []
    for cve in day_cves:
        scored = score_cve_record(cve)
        if scored and scored.get('scoreBreakdown'):
            scored_cves.append(scored['scoreBreakdown'])
    
    if not scored_cves:
        return {
            'root_cause_analysis': None,
            'severity_and_impact': None,
            'software_identification': None,
            'patch_information': None,
            'total_cves': len(day_cves)
        }
    
    # Calculate averages (convert to percentages)
    averages = {}
    for category in ['rootCauseAnalysis', 'severityAndImpactContext', 
                     'softwareIdentification', 'patchinfo']:
        scores = [score.get(category, 0) for score in scored_cves]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        # Convert to percentage based on max points
        if category == 'rootCauseAnalysis':
            avg_percentage = (avg_score / 15) * 100
            key = 'root_cause_analysis'
        elif category == 'severityAndImpactContext':
            avg_percentage = (avg_score / 15) * 100  
            key = 'severity_and_impact'
        elif category == 'softwareIdentification':
            avg_percentage = (avg_score / 10) * 100
            key = 'software_identification'
        else:  # patchinfo
            avg_percentage = (avg_score / 10) * 100
            key = 'patch_information'
            
        averages[key] = round(avg_percentage, 2)
    
    averages['total_cves'] = len(day_cves)
    return averages

def _calculate_rolling_averages(daily_trends: Dict[str, Dict], 
                               window_days: int = 7) -> Dict[str, Dict]:
    """Calculate rolling N-day averages from daily trends."""
    rolling_data = {}
    
    sorted_dates = sorted(daily_trends.keys())
    
    for i, date in enumerate(sorted_dates):
        if i < window_days - 1:
            # Not enough data for full window
            rolling_data[date] = None
            continue
        
        # Get data for the window
        window_dates = sorted_dates[i - window_days + 1:i + 1]
        window_data = []
        
        for window_date in window_dates:
            day_data = daily_trends[window_date]
            if day_data and any(v is not None for k, v in day_data.items() if k != 'total_cves'):
                window_data.append(day_data)
        
        if not window_data:
            rolling_data[date] = None
            continue
        
        # Calculate rolling averages
        rolling_averages = {}
        for category in ['root_cause_analysis', 'severity_and_impact',
                        'software_identification', 'patch_information']:
            values = [d[category] for d in window_data if d[category] is not None]
            if values:
                rolling_averages[category] = round(sum(values) / len(values), 2)
            else:
                rolling_averages[category] = None
        
        rolling_averages['total_cves'] = sum(d['total_cves'] for d in window_data)
        rolling_averages['days_in_average'] = len(window_data)
        
        rolling_data[date] = rolling_averages
    
    return rolling_data

def _get_period_average_scores(daily_data: Dict[str, List], 
                              date_list: List[str]) -> Optional[Dict[str, float]]:
    """Calculate average scores for a period (list of dates)."""
    all_scores = []
    
    for date in date_list:
        if date in daily_data:
            all_scores.extend(daily_data[date])
    
    if not all_scores:
        return None
    
    # Calculate averages for each category
    averages = {}
    for category in ['rootCauseAnalysis', 'severityAndImpactContext',
                     'softwareIdentification', 'patchinfo']:
        scores = [score.get(category, 0) for score in all_scores]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        # Map to standard names and convert to percentages
        if category == 'rootCauseAnalysis':
            averages['root_cause_analysis'] = (avg_score / 15) * 100
        elif category == 'severityAndImpactContext':
            averages['severity_and_impact'] = (avg_score / 15) * 100
        elif category == 'softwareIdentification':
            averages['software_identification'] = (avg_score / 10) * 100
        else:  # patchinfo
            averages['patch_information'] = (avg_score / 10) * 100
    
    return averages
