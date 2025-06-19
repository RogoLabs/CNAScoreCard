from cnagradecard import data_ingestor
from cnagradecard.scoring_service import ScoringService

def generate_report_cards():
    """
    Fetches, scores, and aggregates all CVE data into a final report card for each CNA.
    """
    scorer = ScoringService()
    recent_cves = data_ingestor.get_cve_records()
    
    all_scores = [scorer.score_cve(cve_record) for cve_record in recent_cves]
    
    # Aggregate the scores by CNA
    cna_reports = {}
    for score in all_scores:
        cna_name = score.get("cna")
        if not cna_name or cna_name == "N/A":
            continue
        
        if cna_name not in cna_reports:
            cna_reports[cna_name] = {"scores": []}
        cna_reports[cna_name]["scores"].append(score)

    # Calculate final grades for each CNA
    for cna, data in cna_reports.items():
        scores = data["scores"]
        total_cves = len(scores)
        
        if total_cves > 0:
            avg_readability = sum(s["readability_score"] for s in scores) / total_cves
            avg_references = sum(s["references_score"] for s in scores) / total_cves
            avg_timeliness = sum(s["timeliness_score"] for s in scores) / total_cves
            overall_avg = (avg_readability + avg_references + avg_timeliness) / 3
            
            data["total_cves_scored"] = total_cves
            data["average_readability_score"] = round(avg_readability, 2)
            data["average_references_score"] = round(avg_references, 2)
            data["average_timeliness_score"] = round(avg_timeliness, 2)
            data["overall_average_score"] = round(overall_avg, 2)
            # Clean up the individual scores from the final report
            del data["scores"]

    return cna_reports
