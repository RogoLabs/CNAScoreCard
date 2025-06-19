from fastapi import FastAPI, HTTPException
from cnagradecard.main import generate_reports

app = FastAPI()

# Generate the report card data and individual CVE scores on startup
cna_report_data, all_cve_scores = generate_reports()

# Sort CVEs by overall score
sorted_cves = sorted(all_cve_scores, key=lambda x: x.get('overall_score', 0), reverse=True)

@app.get("/api/cnas")
def get_all_cnas():
    """
    Returns the entire report card for all CNAs.
    """
    return cna_report_data

@app.get("/api/cna/{cna_name}")
def get_cna_by_name(cna_name: str):
    """
    Returns the report card for a specific CNA.
    """
    if cna_name in cna_report_data:
        return cna_report_data[cna_name]
    else:
        raise HTTPException(status_code=404, detail="CNA not found")

@app.get("/api/cves/top100")
def get_top_100_cves():
    """
    Returns the 100 highest-scoring CVEs.
    """
    return sorted_cves[:100]

@app.get("/api/cves/bottom100")
def get_bottom_100_cves():
    """
    Returns the 100 lowest-scoring CVEs.
    """
    return sorted_cves[-100:]
