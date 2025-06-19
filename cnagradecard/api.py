from fastapi import FastAPI, HTTPException
from cnagradecard.main import generate_report_cards

app = FastAPI()

# Generate the report card data on startup
report_data = generate_report_cards()

@app.get("/api/cnas")
def get_all_cnas():
    """
    Returns the entire report card for all CNAs.
    """
    return report_data

@app.get("/api/cna/{cna_name}")
def get_cna_by_name(cna_name: str):
    """
    Returns the report card for a specific CNA.
    """
    if cna_name in report_data:
        return report_data[cna_name]
    else:
        raise HTTPException(status_code=404, detail="CNA not found")
