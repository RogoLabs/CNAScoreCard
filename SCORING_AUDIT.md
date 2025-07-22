# CNA Scorecard Pipeline: Scoring Logic & Trend Analysis Audit

## Overview
This document maps out the current state of all scoring and trend analysis logic in the CNA Scorecard backend pipeline. It identifies the key files, functions, data flows, and pain points, and will serve as the basis for a deep refactor.

---

## 1. **Key Files & Functions**

### Main Pipeline Entrypoint
- **`run_pipeline.py`**
  - Loads CVE data, filters by date (last 6 months), and orchestrates the scoring pipeline.
  - Calls `generate_cna_scorecards()` (main aggregation/scoring function).
  - Calls `generate_individual_cna_jsons()` for per-CNA JSON output.
  - Handles trend period definitions and passes to downstream functions.

### CVE Scoring Logic
- **`scoring.py`**
  - `score_cve_record(cve)`: Central scoring function. Returns `totalScore` and `scoreBreakdown` for a CVE.
    - **Categories/Weights:**
      - Foundational Completeness: 50 pts (descriptions, problemTypes, affected, references)
      - Root Cause Analysis: 15 pts (CWE)
      - Severity & Impact: 15 pts (CVSS)
      - Software Identification: 10 pts (CPE)
      - Actionable Intelligence: 10 pts (advisory/patch refs)
    - Each category has a dedicated `_calculate_*` function.
    - **Pain Point:** Logic is scattered, some checks are hard to trace or duplicate legacy rules.

### CNA Aggregation & Trend Logic
- **`cna_scorecards.py`**
  - `generate_cna_scorecards(...)`: Main aggregation, computes per-CNA averages, grades, and breakdowns.
  - `_generate_individual_scorecard(...)`: Scores all CVEs for a CNA (current period), computes averages, breakdowns, and field completeness.
  - `_calculate_simple_trend(...)` & `_generate_trend(...)`: Trend logic (some deprecated/mocked, some real).
  - **Pain Point:** Multiple trend logics exist (mock, real, simple). Month-over-month trend is not consistently implemented.
  - `_calculate_score_distribution`: For grade bands (Perfect, Great, etc.).

### Individual CNA JSON Generation
- **`generate_individual_cna_jsons.py`**
  - `generate_individual_cna_json(...)`: Filters recent CVEs, formats per-CVE scores for output, attaches trend and metadata.
  - **Pain Point:** Relies on upstream logic; some field names/logic have drifted from canonical source.

### Completeness/Field Utilization
- **`completeness.py`**
  - `compute_field_utilization`: Calculates % of CNAs using each field.
  - `_custom_check`: Legacy checks for field presence, sometimes duplicated in scoring.

### Data Filtering & Period Handling
- Date filtering for scoring and trends is handled at the pipeline level (main), but some functions accept period args and some do not.
- Trend periods are defined as current/previous 6 months, but month-by-month trend is not always available in output.

---

## 2. **Data Flow Summary**

1. **CVE Data Loading:**
   - `load_cve_records()` loads CVEs, applies date filtering (last 6 months for scoring).
2. **CVE Scoring:**
   - Each CVE is scored via `score_cve_record()`.
3. **CNA Aggregation:**
   - CVEs are grouped by CNA; averages, grades, and breakdowns are calculated.
4. **Trend Calculation:**
   - Trend logic is applied (current vs previous period, sometimes month-by-month, sometimes mocked).
5. **Output:**
   - Per-CNA JSON files are generated, including recent CVEs, scores, and trends.

---

## 3. **Pain Points & Technical Debt**

- **Multiple/Conflicting Trend Implementations:**
  - `_generate_trend` (mock), `_calculate_simple_trend` (real, but limited), and ad hoc logic in different places.
- **Date Filtering/Period Awareness:**
  - Some functions rely on upstream date filtering, others accept period args; not all are robust to timezone/format issues.
- **Scoring Logic Duplication:**
  - Some category checks are duplicated (e.g., field presence in both completeness and scoring).
- **Legacy/Unused Fields:**
  - Some outputs still reference old field names or structures.
- **Testability:**
  - Scoring and trend logic are not well isolated for unit testing.

---

## 4. **Summary Table: Key Functions & Responsibilities**

| File                      | Function                           | Purpose/Notes                              |
|---------------------------|------------------------------------|--------------------------------------------|
| scoring.py                | score_cve_record                   | CVE scoring (total & breakdown)            |
| scoring.py                | _calculate_*                       | Category-specific scoring logic             |
| cna_scorecards.py         | generate_cna_scorecards            | Main aggregation, per-CNA scoring          |
| cna_scorecards.py         | _generate_individual_scorecard     | Per-CNA detailed scoring                   |
| cna_scorecards.py         | _calculate_simple_trend            | Month-over-month trend (limited)           |
| cna_scorecards.py         | _generate_trend (deprecated)       | Mock trend (should be removed)             |
| run_pipeline.py           | main                               | Pipeline orchestration, date filtering     |
| generate_individual_cna_jsons.py | generate_individual_cna_json | Per-CNA JSON output, attaches trend        |
| completeness.py           | compute_field_utilization          | Field usage stats                          |
| completeness.py           | _custom_check                      | Legacy field checks                        |

---

## 5. **Recommendations for Refactor**

- **Unify trend logic:** One canonical month-by-month trend calculation, available in all outputs.
- **Centralize scoring:** All scoring logic in one module, with clear, testable category functions.
- **Explicit period handling:** All aggregation functions should accept explicit date/period args.
- **Remove legacy code:** Delete deprecated/mock trend code and unused fields.
- **Add tests:** Unit tests for each scoring/trend function, with fixtures for edge cases.
- **Document everything:** Inline docstrings and a pipeline-level README for future maintainers.

---

*This audit can be used as a checklist and reference for the deep refactor.*
