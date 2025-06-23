from cnascorecard import data_ingestor
from cnascorecard.scoring_service import ScoringService

def generate_reports():
    """
    Fetches, scores, and aggregates all CVE data.
    Returns a tuple containing:
    1. A final report card for each CNA.
    2. A list of all individual CVE scores.
    """
    print("Starting to generate reports...")
    scorer = ScoringService()
    
    print("Fetching recent CVE records...")
    recent_cves = data_ingestor.get_cve_records()
    print(f"Found {len(recent_cves)} CVE records to process.")

    print("Fetching full CNA list...")
    all_cnas = data_ingestor.get_cna_list()
    if all_cnas:
        print(f"Found {len(all_cnas)} total CNAs.")

    # Initialize CVSS and CWE counters for each CNA
    cna_reports = {}
    for cna_info in all_cnas:
        cna_name = cna_info.get("shortName")
        if cna_name and cna_name not in cna_reports:
            cna_reports[cna_name] = {
                "cna": cna_name,
                "total_cves": 0,
                "scores": [],
                "cvss_count": 0,
                "cwe_count": 0
            }
    
    print("Scoring all recent CVEs...")
    for cve in recent_cves:
        cve_score = scorer.score_cve(cve)
        if cve_score:
            cna = cve_score["cna"]
            if cna not in cna_reports:
                cna_reports[cna] = {
                    "cna": cna,
                    "total_cves": 0,
                    "scores": [],
                    "cvss_count": 0,
                    "cwe_count": 0
                }
            cna_reports[cna]["scores"].append(cve_score)
            cna_reports[cna]["total_cves"] += 1
            
            # Count CVSS and CWE presence
            if cve_score.get("has_cvss", False):
                cna_reports[cna]["cvss_count"] += 1
            if cve_score.get("has_cwe", False):
                cna_reports[cna]["cwe_count"] += 1
    print("Finished scoring CVEs.")

    # Create all_scores list from the scores stored in each CNA's data
    all_scores = []
    for cna_data in cna_reports.values():
        if "scores" in cna_data:
            all_scores.extend(cna_data["scores"])

    print("Aggregating scores by CNA...")
    # Aggregate the scores by CNA
    for score in all_scores:
        cna_name = score.get("cna")
        if not cna_name or cna_name == "N/A":
            continue
        
        if cna_name not in cna_reports:
            cna_reports[cna_name] = {"scores": []}
        cna_reports[cna_name]["scores"].append(score)
    print("Finished aggregating scores.")

    print("Calculating final grades for each CNA...")
    # Calculate final grades for each CNA with recent CVEs
    for cna, data in cna_reports.items():
        scores = data["scores"]
        total_cves = len(scores)
        
        if total_cves > 0:
            avg_readability = sum(s["readability_score"] for s in scores) / total_cves
            avg_references = sum(s["references_score"] for s in scores) / total_cves
            avg_timeliness = sum(s["timeliness_score"] for s in scores) / total_cves
            avg_completeness = sum(s["completeness_score"] for s in scores) / total_cves
            overall_avg = (avg_readability + avg_references + avg_timeliness + avg_completeness) / 4
            
            data["total_cves_scored"] = total_cves
            data["average_readability_score"] = round(avg_readability, 2)
            data["average_references_score"] = round(avg_references, 2)
            data["average_timeliness_score"] = round(avg_timeliness, 2)
            data["average_completeness_score"] = round(avg_completeness, 2)
            data["overall_average_score"] = round(overall_avg, 2)
            # Calculate CVSS and CWE percentages
            data["percentage_with_cvss"] = round((data.get("cvss_count", 0) / total_cves) * 100, 1) if total_cves > 0 else 0.0
            data["percentage_with_cwe"] = round((data.get("cwe_count", 0) / total_cves) * 100, 1) if total_cves > 0 else 0.0
            # Clean up the individual scores from the final report
            del data["scores"]

    print("Adding CNAs with no recent publications...")
    # Add CNAs that have not published recently
    if all_cnas:
        for cna_info in all_cnas:
            cna_name = cna_info.get("shortName")
            if cna_name and cna_name not in cna_reports:
                cna_reports[cna_name] = {
                    "total_cves_scored": 0,
                    "average_readability_score": 0,
                    "average_references_score": 0,
                    "average_timeliness_score": 0,
                    "average_completeness_score": 0,
                    "overall_average_score": 0,
                    "message": "No CVEs published in the last 6 months"
                }
    print("Finished adding inactive CNAs.")
    
    print("Calculating CVSS and CWE percentages...")
    # Calculate CVSS and CWE percentages for each CNA
    for cna, data in cna_reports.items():
        total_cves = data["total_cves_scored"]
        cvss_count = data.get("cvss_count", 0)
        cwe_count = data.get("cwe_count", 0)
        
        data["cvss_percentage"] = round((cvss_count / total_cves) * 100, 1) if total_cves > 0 else 0.0
        data["cwe_percentage"] = round((cwe_count / total_cves) * 100, 1) if total_cves > 0 else 0.0
    print("Finished calculating percentages.")
    
    print("Report generation complete.")
    return cna_reports, list(cna_reports.values())
