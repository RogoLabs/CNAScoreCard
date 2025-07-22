"""
aggregation.py: CNA-level aggregation and trend logic for CNA Scorecard pipeline.
"""
from typing import List, Dict, Tuple, Any
from datetime import datetime

def aggregate_cna_scores(scored_cves: List[Dict], periods: List[Tuple[datetime, datetime]]) -> Dict[str, Any]:
    """
    Groups scored CVEs by CNA and by period (e.g., month or 6-month window).
    Returns per-CNA dict with scoring, monthly trends, and all aggregation fields needed for output.
    Output matches new schema.
    """
    from collections import defaultdict
    from trend import calculate_monthly_trend, summarize_trend

    cna_cves = defaultdict(list)
    for cve in scored_cves:
        cna = cve.get('assigningCna', 'Unknown')
        cna_cves[cna].append(cve)

    # Load enhanced CNA metadata
    import os, json
    cna_list_path = os.path.join(os.path.dirname(__file__), '..', 'web', 'data', 'cna_list.json')
    cna_metadata_map = {}
    if os.path.exists(cna_list_path):
        with open(cna_list_path, 'r') as f:
            for entry in json.load(f):
                cna_metadata_map[entry.get('shortName', '').lower()] = entry

    cna_outputs = {}
    for cna, cves in cna_cves.items():
        # Use only the actual recent_cves for all scoring and output
        recent_cves = [cve for cve in cves if cve.get('recent', True)]
        # Defensive: if recent_cves is empty, output zeros for all averages
        if not recent_cves:
            cna_outputs[cna] = {
                'cna_info': [],
                'cna_scoring': [{
                    'overall_average_score': 0.0,
                    'average_foundational_completeness': 0.0,
                    'average_root_cause_analysis': 0.0,
                    'average_software_identification': 0.0,
                    'average_severity_context': 0.0,
                    'average_patchinfo': 0.0,
                    'trend_direction': 'N/A',
                    'trend_description': '',
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

        # Merge in metadata if available
        # Robust metadata lookup: try lower(), original, and case-insensitive fallback
        meta = cna_metadata_map.get(str(cna).lower())
        if not meta:
            meta = cna_metadata_map.get(str(cna))
        if not meta:
            # Fallback: case-insensitive search
            for key in cna_metadata_map:
                if key.lower() == str(cna).lower():
                    meta = cna_metadata_map[key]
                    break
        if not meta:
            meta = {}
        # Explicitly construct cna_info with only allowed fields
        cna_info = {
            'cna': cna,
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
        if cna.lower() == 'fortinet':
            print(f"[DEBUG] Fortinet patchinfo avg: {cat_avgs.get('patchinfo', 0)} (sum: {cat_sums.get('patchinfo', 0)}, count: {len(recent_cves)})")
        # CNA scoring (ensure all expected fields are present)
        total_cves = len(cves)
        total_cves_scored = sum(1 for cve in cves if cve.get('totalScore', 0) > 0)
        cna_scoring = {
            'total_cves': total_cves,
            'total_cves_scored': total_cves_scored,
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
                'assigningCna': cve.get('assigningCna', ''),
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
        cna_outputs[cna] = {
            'cna_info': [cna_info],
            'cna_scoring': [cna_scoring],
            'cve_scoring': cve_scoring
        }
    return cna_outputs

