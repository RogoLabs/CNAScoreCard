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

    print("Scoring all recent CVEs...")
    all_scores = [scorer.score_cve(cve_record) for cve_record in recent_cves]
    print("Finished scoring CVEs.")

    print("Aggregating scores by CNA...")
    # Aggregate the scores by CNA
    cna_reports = {}
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
    
    print("Report generation complete.")
    return cna_reports, all_scores
