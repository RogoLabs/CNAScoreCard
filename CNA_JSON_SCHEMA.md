# Canonical CNA JSON Schema Proposal

This schema is designed for all files in `web/data/cna/`. It ensures:
- **All data needed by the frontend is present**
- **Consistent, well-ordered structure**
- **Separation of CNA info, CNA scoring, and CVE scoring into arrays**
- **Extensibility and clarity for future maintainers**

---

## Top-Level Structure
```json
{
  "cna_info": [ ... ],        // Array of CNA metadata objects
  "cna_scoring": [ ... ],    // Array of CNA-level scoring/aggregation objects
  "cve_scoring": [ ... ]     // Array of recent CVE scoring objects
}
```

---

## 1. `cna_info` Array (length = 1, but array for extensibility)
Each object contains metadata and organizational info about the CNA.

```json
{
  "cna": "string",                   // Short name (e.g., "fedora")
  "organizationName": "string",      // Full org name
  "scope": "string",                 // Scope/description
  "advisories": [ { "label": "string", "url": "string" } ],
  "email": [ { "label": "string", "emailAddr": "string" } ],
  "officialCnaID": "string",
  "cnaTypes": [ "string", ... ],
  "country": "string",
  "disclosurePolicy": [ { "label": "string", "language": "string", "url": "string" } ],
  "rootCnaInfo": { "shortName": "string", "organizationName": "string" },
  "rank": integer,
  "active_cna_count": integer,
  "percentile": float
}
```

---

## 2. `cna_scoring` Array (length = 1, but array for extensibility)
Each object contains all CNA-level scoring, averages, and trend info.

```json
{
  "overall_average_score": float,
  "average_foundational_completeness": float,
  "average_root_cause_analysis": float,
  "average_software_identification": float,
  "average_severity_context": float,
  "average_actionable_intelligence": float,
  "trend_direction": "string",        // e.g., "improving", "steady", "declining"
  "trend_description": "string",      // Human-readable summary
  "monthly_trends": [ float, ... ]     // Array of 6 monthly average scores
}
```

---

## 3. `cve_scoring` Array
Each object contains all recent CVEs (last 6 months), with full scoring breakdown.

```json
{
  "cveId": "string",
  "assigningCna": "string",
  "datePublished": "string (ISO 8601)",
  "totalCveScore": integer,
  "scoreBreakdown": {
    "foundationalCompleteness": integer,
    "rootCauseAnalysis": integer,
    "softwareIdentification": integer,
    "severityAndImpactContext": integer,
    "actionableIntelligence": integer
  }
}
```

---

## Notes
- All arrays are used for extensibility and future multi-period/variant support.
- All fields required by the frontend are present; additional fields can be added as needed.
- Field types are explicit and documented.

---

*Please review this schema. Once approved, it will be enforced in all pipeline outputs and validated by tests.*
