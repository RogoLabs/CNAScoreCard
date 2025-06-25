from cnascorecard import data_ingestor
from cnascorecard.eas_scorer import calculate_eas

def generate_reports():
    """
    Fetches, scores, and aggregates all CVE data.
    Returns a tuple containing:
    1. A final report card for each CNA.
    2. A list of all individual CVE scores.
    """
    print("Starting to generate reports...")
    
    print("Fetching recent CVE records...")
    recent_cves = data_ingestor.get_cve_records()
    print(f"Found {len(recent_cves)} CVE records to process.")

    print("Fetching full CNA list...")
    all_cnas = data_ingestor.get_cna_list()
    if all_cnas:
        print(f"Found {len(all_cnas)} total CNAs.")

    # Initialize CNA reports
    cna_reports = {}
    if all_cnas:
        for cna_info in all_cnas:
            cna_name = cna_info.get("shortName")
            if cna_name and cna_name not in cna_reports:
                cna_reports[cna_name] = {
                    "cna": cna_name,
                    "total_cves": 0,
                    "scores": []
                }
    
    print("Scoring all recent CVEs...")
    all_scores = []
    for cve in recent_cves:
        cve_score = calculate_eas(cve)
        if cve_score:
            all_scores.append(cve_score)
            cna = cve_score["assigningCna"]
            if cna not in cna_reports:
                cna_reports[cna] = {
                    "cna": cna,
                    "total_cves": 0,
                    "scores": []
                }
            cna_reports[cna]["scores"].append(cve_score)
            cna_reports[cna]["total_cves"] += 1
    print("Finished scoring CVEs.")

    print("Aggregating scores by CNA...")
    # Aggregate the scores by CNA
    for score in all_scores:
        cna_name = score.get("assigningCna")
        if not cna_name or cna_name == "N/A":
            continue
        
        if cna_name not in cna_reports:
            cna_reports[cna_name] = {"scores": []}
        # Score is already added above, no need to add again
    print("Finished aggregating scores.")

    print("Calculating final grades for each CNA...")
    # Calculate final grades for each CNA with recent CVEs
    for cna, data in cna_reports.items():
        scores = data["scores"]
        total_cves = len(scores)
        
        if total_cves > 0:
            # Calculate average EAS score and breakdown
            avg_total_eas = sum(s["totalEasScore"] for s in scores) / total_cves
            avg_foundational = sum(s["scoreBreakdown"]["foundationalCompleteness"] for s in scores) / total_cves
            avg_root_cause = sum(s["scoreBreakdown"]["rootCauseAnalysis"] for s in scores) / total_cves
            avg_software_identification = sum(s["scoreBreakdown"]["softwareIdentification"] for s in scores) / total_cves
            avg_severity = sum(s["scoreBreakdown"]["severityAndImpactContext"] for s in scores) / total_cves
            avg_actionable = sum(s["scoreBreakdown"]["actionableIntelligence"] for s in scores) / total_cves
            avg_format = sum(s["scoreBreakdown"]["dataFormatAndPrecision"] for s in scores) / total_cves
            
            data["total_cves_scored"] = total_cves
            data["average_eas_score"] = int(round(avg_total_eas, 2)) if round(avg_total_eas, 2) % 1 == 0 else round(avg_total_eas, 2)
            data["overall_average_score"] = int(round(avg_total_eas, 2)) if round(avg_total_eas, 2) % 1 == 0 else round(avg_total_eas, 2)  # For compatibility
            data["average_foundational_completeness"] = int(round(avg_foundational, 2)) if round(avg_foundational, 2) % 1 == 0 else round(avg_foundational, 2)
            data["average_root_cause_analysis"] = int(round(avg_root_cause, 2)) if round(avg_root_cause, 2) % 1 == 0 else round(avg_root_cause, 2)
            data["average_software_identification"] = int(round(avg_software_identification, 2)) if round(avg_software_identification, 2) % 1 == 0 else round(avg_software_identification, 2)
            data["average_severity_context"] = int(round(avg_severity, 2)) if round(avg_severity, 2) % 1 == 0 else round(avg_severity, 2)
            data["average_actionable_intelligence"] = int(round(avg_actionable, 2)) if round(avg_actionable, 2) % 1 == 0 else round(avg_actionable, 2)
            data["average_data_format_precision"] = int(round(avg_format, 2)) if round(avg_format, 2) % 1 == 0 else round(avg_format, 2)
            
            # Clean up the individual scores from the final report
            del data["scores"]

    print("Calculating percentiles for active CNAs...")
    # Calculate percentiles and ranks for CNAs with recent CVEs
    active_cnas = [data for data in cna_reports.values() if data.get("total_cves_scored", 0) > 0]
    # Sort active CNAs by average_eas_score descending
    sorted_active = sorted(active_cnas, key=lambda d: d["average_eas_score"], reverse=True)
    # Assign rank (1 = best)
    for idx, data in enumerate(sorted_active, 1):
        data["rank"] = idx
        data["active_cna_count"] = len(sorted_active)
    active_scores = [data["average_eas_score"] for data in sorted_active]
    if active_scores:
        # Sort scores to calculate percentiles
        sorted_scores = sorted(active_scores)
        for cna, data in cna_reports.items():
            if data.get("total_cves_scored", 0) > 0:
                score = data["average_eas_score"]
                rank = sum(1 for s in sorted_scores if s <= score)
                percentile = (rank / len(sorted_scores)) * 100
                data["percentile"] = round(percentile, 1)
            else:
                data["percentile"] = 0.0

    print("Adding CNAs with no recent publications...")
    # Add CNAs that have not published recently
    if all_cnas:
        for cna_info in all_cnas:
            cna_name = cna_info.get("shortName")
            if cna_name and cna_name not in cna_reports:
                cna_reports[cna_name] = {
                    "cna": cna_name,
                    "total_cves": 0,
                    "total_cves_scored": 0,
                    "average_eas_score": 0,
                    "overall_average_score": 0,
                    "average_foundational_completeness": 0,
                    "average_root_cause_analysis": 0,
                    "average_software_identification": 0,
                    "average_severity_context": 0,
                    "average_actionable_intelligence": 0,
                    "average_data_format_precision": 0,
                    "message": "No CVEs published in the last 6 months"
                }
    print("Finished adding inactive CNAs.")
    
    print("Report generation complete.")
    return cna_reports, all_scores
