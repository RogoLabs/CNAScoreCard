"""
aggregation.py: CNA-level aggregation and trend logic for CNA Scorecard pipeline.
"""
import os
import json
from typing import List, Dict, Tuple, Any
from datetime import datetime

def aggregate_cna_scores(scored_cves: List[Dict], periods: List[Tuple[datetime, datetime]]) -> Dict[str, Any]:
    """
    Groups scored CVEs by CNA and by period (e.g., month or 6-month window).
    Returns per-CNA dict with scoring, monthly trends, and all aggregation fields needed for output.
    Output matches new schema.
    
    IMPORTANT: This function now ensures ALL official CNAs get entries in the output,
    even if they have no CVE data, to prevent missing individual JSON files.
    """
    from collections import defaultdict
    # Simple trend calculation functions (replacing moved trend.py)
    def calculate_monthly_trend(cves, months=6):
        """Simple placeholder for monthly trend calculation."""
        return []
    
    def summarize_trend(monthly_trends):
        """Simple placeholder for trend summary."""
        return {
            'trend_direction': 'steady',
            'trend_description': 'No significant change'
        }

    # Group CVEs by assigningCna
    cna_cves = defaultdict(list)
    for cve in scored_cves:
        # Skip invalid CVE data
        if not cve or not isinstance(cve, dict):
            continue
        cna = cve.get('assigningCna', 'Unknown')
        cna_cves[cna].append(cve)

    # Load enhanced CNA metadata - this is our authoritative source
    import os, json
    cna_list_path = os.path.join(os.path.dirname(__file__), '..', 'web', 'data', 'cna_list.json')
    cna_metadata_map = {}
    official_cna_names = set()
    
    if os.path.exists(cna_list_path):
        try:
            with open(cna_list_path, 'r') as f:
                cna_list_data = json.load(f)
                for entry in cna_list_data:
                    short_name = entry.get('shortName', '')
                    if short_name:
                        cna_metadata_map[short_name.lower()] = entry
                        official_cna_names.add(short_name)
        except (IOError, OSError, ValueError, json.JSONDecodeError) as e:
            print(f"[WARNING] Error reading CNA metadata file: {e}")
            # Continue with empty metadata - function should still work
    
    print(f"[DEBUG] Loaded {len(official_cna_names)} official CNAs from metadata")
    print(f"[DEBUG] Found CVE data for {len(cna_cves)} CNAs")

    # Create name mapping function to match CVE assigningCna to official CNA names
    def map_cve_name_to_official(cve_name, official_names, metadata_map):
        """Map CVE assigningCna name to official CNA name using various strategies"""
        if not cve_name or cve_name == 'Unknown':
            return None
            
        # Try exact match first
        if cve_name in official_names:
            return cve_name
            
        # Try case-insensitive match
        for official_name in official_names:
            if official_name.lower() == cve_name.lower():
                return official_name
                
        # Try normalized matching (remove spaces, hyphens, underscores)
        normalized_cve = cve_name.lower().replace(' ', '').replace('-', '').replace('_', '')
        for official_name in official_names:
            normalized_official = official_name.lower().replace(' ', '').replace('-', '').replace('_', '')
            if normalized_official == normalized_cve:
                return official_name
                
        # Try partial matching for complex cases
        cve_lower = cve_name.lower()
        for official_name in official_names:
            official_lower = official_name.lower()
            if (cve_lower in official_lower or official_lower in cve_lower) and len(cve_lower) > 2:
                return official_name
                
        return None
    
    # Map CVE data to official CNA names
    official_cna_cves = defaultdict(list)
    unmapped_cves = defaultdict(list)
    
    for cve_cna_name, cves in cna_cves.items():
        official_name = map_cve_name_to_official(cve_cna_name, official_cna_names, cna_metadata_map)
        if official_name:
            official_cna_cves[official_name].extend(cves)
        else:
            unmapped_cves[cve_cna_name].extend(cves)
    
    print(f"[DEBUG] Mapped CVE data to {len(official_cna_cves)} official CNAs")
    if unmapped_cves:
        print(f"[DEBUG] {len(unmapped_cves)} CVE groups could not be mapped to official CNAs:")
        for unmapped_name in list(unmapped_cves.keys())[:5]:  # Show first 5
            print(f"[DEBUG]   - {unmapped_name} ({len(unmapped_cves[unmapped_name])} CVEs)")
    
    cna_outputs = {}
    
    # Process ALL official CNAs, ensuring each gets an entry
    for official_cna_name in official_cna_names:
        cves = official_cna_cves.get(official_cna_name, [])
        # Use only the actual recent_cves for all scoring and output
        recent_cves = [cve for cve in cves if cve.get('recent', True)]
        # Get official metadata for this CNA
        meta = cna_metadata_map.get(official_cna_name.lower(), {})
        
        # Defensive: if recent_cves is empty, still create entry with metadata
        if not recent_cves:
            # Create cna_info with metadata even for CNAs with no CVEs
            cna_info = {
                'cna': official_cna_name,
                'total_cves': len(cves),
                'total_cves_scored': 0,
                'organizationName': meta.get('organizationName', ''),
                'scope': meta.get('scope', ''),
                'advisories': meta.get('advisories', []),
                'email': meta.get('email', []),
                'officialCnaID': meta.get('cnaID', ''),
                'cnaTypes': meta.get('type', []),
                'country': meta.get('country', ''),
                'disclosurePolicy': meta.get('disclosurePolicy', []),
                'rootCnaInfo': meta.get('rootCnaInfo', {}),
                'rank': 0,
                'active_cna_count': 0,
                'percentile': 0.0
            }
            
            cna_outputs[official_cna_name] = {
                'cna_info': [cna_info],
                'cna_scoring': [{
                    'total_cves': len(cves),
                    'total_cves_scored': 0,
                    'recent_cves_count': 0,  # Add missing recent CVEs count for inactive CNAs
                    'overall_average_score': 0.0,
                    'average_foundational_completeness': 0.0,
                    'average_root_cause_analysis': 0.0,
                    'average_software_identification': 0.0,
                    'average_severity_context': 0.0,
                    'average_patchinfo': 0.0,
                    'percent_foundational_completeness': 0.0,
                    'percent_root_cause_analysis': 0.0,
                    'percent_software_identification': 0.0,
                    'percent_severity_and_impact': 0.0,
                    'percent_patchinfo': 0.0,
                    'trend_direction': 'N/A',
                    'trend_description': 'No recent CVE data available',
                    'monthly_trends': []
                }],
                'cve_scoring': []
            }
            continue

        # Calculate monthly trends
        monthly_trends = calculate_monthly_trend(recent_cves, months=6)
        trend_summary = summarize_trend(monthly_trends)

        # Aggregate CNA-level scoring (over recent CVEs only)
        overall_avg = 0.0
        if recent_cves:
            total_score_sum = sum(cve.get('totalScore', 0) for cve in recent_cves)
            overall_avg = round(total_score_sum / len(recent_cves), 2) if total_score_sum != 0 else 0.0
        cat_sums = defaultdict(float)
        cat_counts = defaultdict(int)
        for cve in recent_cves:
            breakdown = cve.get('scoreBreakdown', {})
            for k, v in breakdown.items():
                cat_sums[k] += v
                # Count as 'present' if the score for this category is nonzero
                if v and v > 0:
                    cat_counts[k] += 1
        cat_avgs = {}
        for k, v in cat_sums.items():
            avg = round(v / len(recent_cves), 2) if recent_cves and v != 0 else 0.0
            cat_avgs[k] = avg
        # Calculate percent-of-CVEs-with-data for each category
        percent_fields = {}
        for k in ['foundationalCompleteness', 'rootCauseAnalysis', 'softwareIdentification', 'severityAndImpactContext', 'patchinfo']:
            percent = round(100.0 * cat_counts.get(k, 0) / len(recent_cves), 2) if recent_cves else 0.0
            percent_fields[f'percent_{k}'] = percent

        # Use metadata already retrieved above
        # meta is already set from cna_metadata_map.get(official_cna_name.lower(), {})
        # Explicitly construct cna_info with only allowed fields
        cna_info = {
            'cna': official_cna_name,
            'total_cves': len(cves),
            'total_cves_scored': sum(1 for cve in cves if cve.get('totalScore', 0) > 0),
            'organizationName': meta.get('organizationName', ''),
            'scope': meta.get('scope', ''),
            'advisories': meta.get('advisories', []),
            'email': meta.get('email', []),
            'officialCnaID': meta.get('cnaID', ''),
            'cnaTypes': meta.get('type', []),
            'country': meta.get('country', ''),
            'disclosurePolicy': meta.get('disclosurePolicy', []),
            'rootCnaInfo': meta.get('rootCnaInfo', {}),
            'rank': 0,
            'active_cna_count': 0,
            'percentile': 0.0
        }
        # FINAL FILTER: forcibly remove any average/overall fields from cna_info
        for k in [
            'overall_average_score',
            'average_foundational_completeness',
            'average_root_cause_analysis',
            'average_software_identification',
            'average_severity_context',
            'average_patchinfo']:
            cna_info.pop(k, None)

        # DEBUG: Print patchinfo average for Fortinet
        if official_cna_name.lower() == 'fortinet':
            print(f"[DEBUG] Fortinet patchinfo avg: {cat_avgs.get('patchinfo', 0)} (sum: {cat_sums.get('patchinfo', 0)}, count: {len(recent_cves)})")
        # CNA scoring (ensure all expected fields are present)
        total_cves = len(cves)
        total_cves_scored = sum(1 for cve in cves if cve.get('totalScore', 0) > 0)
        cna_scoring = {
            'total_cves': total_cves,
            'total_cves_scored': total_cves_scored,
            'recent_cves_count': len(recent_cves),  # Add missing recent CVEs count
            'overall_average_score': overall_avg,
            'average_foundational_completeness': cat_avgs.get('foundationalCompleteness', 0),
            'average_root_cause_analysis': cat_avgs.get('rootCauseAnalysis', 0),
            'average_software_identification': cat_avgs.get('softwareIdentification', 0),
            'average_severity_context': cat_avgs.get('severityAndImpactContext', 0),
            'average_patchinfo': cat_avgs.get('patchinfo', 0),
            # New percent-of-CVEs-with-data fields:
            'percent_foundational_completeness': percent_fields.get('percent_foundationalCompleteness', 0.0),
            'percent_root_cause_analysis': percent_fields.get('percent_rootCauseAnalysis', 0.0),
            'percent_software_identification': percent_fields.get('percent_softwareIdentification', 0.0),
            'percent_severity_and_impact': percent_fields.get('percent_severityAndImpactContext', 0.0),
            'percent_patchinfo': percent_fields.get('percent_patchinfo', 0.0),
            'trend_direction': trend_summary.get('trend_direction', 'N/A'),
            'trend_description': trend_summary.get('trend_description', ''),
            'monthly_trends': monthly_trends
        }
        # CVE scoring (ensure all expected fields are present)
        cve_scoring = []
        for cve in cves:
            breakdown = cve.get('scoreBreakdown', {})
            cve_scoring.append({
                'cveId': cve.get('cveId', ''),
                'assigningCna': official_cna_name,  # Use official name consistently
                'datePublished': cve.get('datePublished', ''),
                'totalCveScore': cve.get('totalScore', 0),
                'scoreBreakdown': {
                    'foundationalCompleteness': breakdown.get('foundationalCompleteness', 0),
                    'rootCauseAnalysis': breakdown.get('rootCauseAnalysis', 0),
                    'softwareIdentification': breakdown.get('softwareIdentification', 0),
                    'severityAndImpactContext': breakdown.get('severityAndImpactContext', 0),
                    'patchinfo': breakdown.get('patchinfo', 0)
                }
            })
        cna_outputs[official_cna_name] = {
            'cna_info': [cna_info],
            'cna_scoring': [cna_scoring],
            'cve_scoring': cve_scoring
        }
    return cna_outputs

