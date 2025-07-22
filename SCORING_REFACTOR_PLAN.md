# CNA Scorecard Pipeline: Scoring & Trend Refactor Architecture

## 1. Goals
- **Reliability:** Deterministic, transparent scoring for every CVE and CNA.
- **Clarity:** All scoring/trend logic centralized and documented.
- **Flexibility:** Easy to add/change scoring rules or trend periods.
- **Testability:** Unit tests for every scoring and trend function.
- **Cleanliness:** No legacy, mock, or unused code/files.

---

## 2. Module Structure

### `/cnascorecard_pipeline/scoring.py`
- **`score_cve(cve: dict) -> dict`**
  - Returns: `{ 'total': int, 'breakdown': {...}, 'assigningCna': str }`
  - Single source of truth for all category weights, rules, and field checks.
  - All category functions (foundational, root cause, etc.) are pure and documented.

### `/cnascorecard_pipeline/aggregation.py` *(NEW)*
- **`aggregate_cna_scores(cves: List[dict], periods: List[Tuple[start, end]]) -> dict`**
  - Groups CVEs by CNA and by period (month or 6-month window).
  - Returns: `{ cna_id: { 'scores': [...], 'monthly_trends': [...], ... } }`
  - Handles all period filtering, averaging, and edge cases (no CVEs, invalid CVEs).

### `/cnascorecard_pipeline/trend.py` *(NEW)*
- **`calculate_monthly_trend(cna_scores: List[dict]) -> List[float]`**
  - Given a CNA's scored CVEs, outputs an array of 6 monthly average scores.
  - Also returns trend direction/description for last 2 periods.

### `/cnascorecard_pipeline/output.py`
- **`write_json(data, filename, out_dir="../web/data")`**
  - No change (remains the output sink).

### `/cnascorecard_pipeline/completeness.py`
- **`compute_field_utilization(cve_records, field_list)`**
  - Remains for field usage stats; no scoring logic duplication.

---

## 3. Data Flow
1. **CVE Loading:**
   - Load all CVEs for the relevant date range (optionally all CVEs for trend).
2. **Scoring:**
   - Score every CVE with `scoring.score_cve()`.
3. **Aggregation:**
   - Use `aggregation.aggregate_cna_scores()` to group/average by CNA and period.
4. **Trend Calculation:**
   - Use `trend.calculate_monthly_trend()` for each CNA to get month-by-month scores and trend summary.
5. **Output:**
   - Write per-CNA and summary JSON with all scores/trends.

---

## 4. Key Interfaces
- **CVE Score:**
  ```python
  {
    'cveId': str,
    'assigningCna': str,
    'datePublished': str,
    'totalCveScore': int,
    'scoreBreakdown': { ... }
  }
  ```
- **CNA Score Summary:**
  ```python
  {
    'cna': str,
    'overall_average_score': float,
    'monthly_trends': [float, ...],
    'trend_direction': str,
    'trend_description': str,
    ...
  }
  ```

---

## 5. Removal/Cleanup
- Remove all old/deprecated trend functions (`_generate_trend`, etc.)
- Remove any unused scripts or data files (after confirming not needed for new flow)
- Remove scoring logic from any file except `scoring.py` (except completeness)

---

## 6. Testing & Documentation
- Add unit tests for: scoring, aggregation, trend.
- Add/refresh docstrings and a `README.md` for the pipeline.
- Document all scoring weights and rules in one place.

---

## 7. Refactor Steps
1. Implement new `scoring.py` (pure, testable, documented)
2. Implement `aggregation.py` and `trend.py`
3. Refactor pipeline to use new modules
4. Remove legacy code/files
5. Add tests and documentation
6. Validate outputs and performance

---

*Please review this architecture. Once approved, I'll begin implementation step-by-step, with checkpoints at each major milestone.*
