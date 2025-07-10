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
            cna = cve_score.get("assigningCna", "Unknown")
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
            
            data["total_cves_scored"] = total_cves
            data["average_eas_score"] = int(round(avg_total_eas, 2)) if round(avg_total_eas, 2) % 1 == 0 else round(avg_total_eas, 2)
            data["overall_average_score"] = data["average_eas_score"]  # For compatibility
            data["average_foundational_completeness"] = int(round(avg_foundational, 2)) if round(avg_foundational, 2) % 1 == 0 else round(avg_foundational, 2)
            data["average_root_cause_analysis"] = int(round(avg_root_cause, 2)) if round(avg_root_cause, 2) % 1 == 0 else round(avg_root_cause, 2)
            data["average_software_identification"] = int(round(avg_software_identification, 2)) if round(avg_software_identification, 2) % 1 == 0 else round(avg_software_identification, 2)
            data["average_severity_context"] = int(round(avg_severity, 2)) if round(avg_severity, 2) % 1 == 0 else round(avg_severity, 2)
            data["average_actionable_intelligence"] = int(round(avg_actionable, 2)) if round(avg_actionable, 2) % 1 == 0 else round(avg_actionable, 2)
            # Clean up the individual scores from the final report
            del data["scores"]

    print("Calculating percentiles for active CNAs...")
    # Calculate percentiles and ranks for CNAs with recent CVEs
    active_cnas = [data for data in cna_reports.values() if data.get("total_cves_scored", 0) > 0]
    sorted_active = sorted(active_cnas, key=lambda d: d["average_eas_score"], reverse=True)
    for idx, data in enumerate(sorted_active, 1):
        data["rank"] = idx
        data["active_cna_count"] = len(sorted_active)
    active_scores = [data["average_eas_score"] for data in sorted_active]
    if active_scores:
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
                    "message": "No CVEs published in the last 6 months"
                }
    print("Finished adding inactive CNAs.")
    
    print("Report generation complete.")
    return cna_reports, all_scores

def analyze_field_utilization(cve_records, schema_fields):
    """
    Analyze field utilization across all CVE records.
    Returns dicts for heatmap, leaderboards, and breakdowns.
    """
    from collections import defaultdict
    field_counts = defaultdict(int)
    total_cves = len(cve_records)
    for cve in cve_records:
        def check_fields(obj, prefix=""):
            for key, value in obj.items():
                field = f"{prefix}{key}" if prefix else key
                if value is not None and value != [] and value != "":
                    field_counts[field] += 1
                if isinstance(value, dict):
                    check_fields(value, field + ".")
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            check_fields(item, field + ".")
        check_fields(cve)
    # Build utilization stats
    utilization = []
    for field in schema_fields:
        count = field_counts.get(field["name"], 0)
        utilization.append({
            "field": field["name"],
            "description": field.get("description", ""),
            "required": field.get("required", False),
            "utilization": round(100 * count / total_cves, 2) if total_cves else 0
        })
    return utilization

def generate_field_insights_json():
    """
    Generates JSON files for field insights (heatmap, leaderboards, breakdowns).
    """
    import json, os
    # List of 10 automatically-populated CVE program fields to exclude
    excluded_fields = set([
        "cveMetadata.datePublished",
        "cveMetadata.dateUpdated",
        "cveMetadata.dateReserved",
        "cveMetadata.state",
        "cveMetadata.assignerOrgId",
        "cveMetadata.serial",
        "cveMetadata.assignerShortName",
        "cveMetadata.providerMetadata.orgId",
        "cveMetadata.providerMetadata.shortName",
        "cveMetadata.providerMetadata.dateUpdated"
    ])
    # Load schema fields (should be a list of dicts with name, description, required)
    schema_path = os.path.join(os.path.dirname(__file__), "cve_schema_fields.json")
    if not os.path.exists(schema_path):
        print("Schema field definition file missing: cve_schema_fields.json")
        return
    with open(schema_path, "r") as f:
        schema_fields = json.load(f)
    # Exclude the 10 fields from schema_fields
    schema_fields = [f for f in schema_fields if f["name"] not in excluded_fields]
    # Get all CVE records
    cve_records = data_ingestor.get_cve_records()
    utilization = analyze_field_utilization(cve_records, schema_fields)
    # Heatmap data
    heatmap = {u["field"]: u["utilization"] for u in utilization}
    # Leaderboards
    sorted_fields = sorted(utilization, key=lambda x: x["utilization"], reverse=True)
    most_utilized = sorted_fields[:15]
    least_utilized = sorted_fields[-15:]
    # Breakdowns
    required = [u for u in utilization if u["required"]]
    optional = [u for u in utilization if not u["required"]]
    # Output directory
    out_dir = os.path.join(os.path.dirname(__file__), "../web/field-insights/")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "field_utilization.json"), "w") as f:
        json.dump(heatmap, f, indent=2)
    with open(os.path.join(out_dir, "field_leaderboards.json"), "w") as f:
        json.dump({"most_utilized": most_utilized, "least_utilized": least_utilized}, f, indent=2)
    with open(os.path.join(out_dir, "required_fields_breakdown.json"), "w") as f:
        json.dump(required, f, indent=2)
    with open(os.path.join(out_dir, "optional_fields_breakdown.json"), "w") as f:
        json.dump(optional, f, indent=2)
    print("Field insights JSON files generated.")

if __name__ == "__main__":
    cna_reports, all_scores = generate_reports()
    generate_field_insights_json()
    # Save completeness data to both completeness and field-insights folders
    import json, os
    web_dir = os.path.join(os.path.dirname(__file__), "../web")
    completeness_dir = os.path.join(web_dir, "completeness")
    field_insights_dir = os.path.join(web_dir, "field-insights")
    os.makedirs(completeness_dir, exist_ok=True)
    os.makedirs(field_insights_dir, exist_ok=True)
    # Save cna_completeness.json
    cna_completeness_path = os.path.join(completeness_dir, "cna_completeness.json")
    cna_completeness_path2 = os.path.join(field_insights_dir, "cna_completeness.json")
    with open(cna_completeness_path, "w") as f:
        json.dump(list(cna_reports.values()), f, indent=2)
    with open(cna_completeness_path2, "w") as f:
        json.dump(list(cna_reports.values()), f, indent=2)
    # Save completeness_summary.json
    summary_path = os.path.join(completeness_dir, "completeness_summary.json")
    summary_path2 = os.path.join(field_insights_dir, "completeness_summary.json")
    # Assume you have a function or dict for summaryData, else skip
    if 'summaryData' in globals():
        with open(summary_path, "w") as f:
            json.dump(summaryData, f, indent=2)
        with open(summary_path2, "w") as f:
            json.dump(summaryData, f, indent=2)
