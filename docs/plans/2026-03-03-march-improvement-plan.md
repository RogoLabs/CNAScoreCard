# March 2026 Comprehensive Improvement Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix critical bugs, harden CI/CD, refactor Python pipeline and web frontend, and improve test coverage across the entire CNA Scorecard codebase.

**Architecture:** Bottom-up approach: fix critical infrastructure first (CI/CD, bugs), then refactor Python pipeline (dedup, types, error handling, performance), then improve web frontend (CSS/JS consolidation, accessibility, SEO, security), then fill testing gaps.

**Tech Stack:** Python 3.13, vanilla HTML/CSS/JS, GitHub Actions, pytest, Chart.js

---

## Task 1: Fix Broken CVE Data Cache Key

**Files:**
- Modify: `.github/workflows/run-pipeline.yml:49-56`

**Step 1: Fix the cache key**

The cache key `cve-data-${{ github.run_number }}` creates a new cache entry every run, so the cache is never reused. Change to a stable key.

In `.github/workflows/run-pipeline.yml`, replace lines 49-56:

```yaml
    - name: Cache CVE data repository
      id: cache-cve-data
      uses: actions/cache@v4
      with:
        path: cve_data
        key: cve-data-${{ github.run_number }}
        restore-keys: |
          cve-data-
```

With:

```yaml
    - name: Cache CVE data repository
      id: cache-cve-data
      uses: actions/cache@v4
      with:
        path: cve_data
        key: cve-data-v1
        restore-keys: |
          cve-data-
```

**Step 2: Commit**

```bash
git add .github/workflows/run-pipeline.yml
git commit -m "fix: use stable cache key for CVE data to enable cache reuse"
```

---

## Task 2: Fix Hardcoded Year Bug in Ingest

**Files:**
- Modify: `cnascorecard_pipeline/ingest.py:98-106`
- Test: `cnascorecard_pipeline/tests/test_ingest.py`

**Step 1: Write a failing test**

Add to `cnascorecard_pipeline/tests/test_ingest.py`:

```python
def test_get_cve_file_list_uses_current_year(tmp_path, monkeypatch):
    """Verify that recent_years is calculated dynamically, not hardcoded."""
    from datetime import datetime

    cves_dir = tmp_path / "cves"
    # Create year directories for 2026 and 2025
    for year in ["2025", "2026"]:
        year_dir = cves_dir / year / "0xxx"
        year_dir.mkdir(parents=True)
        (year_dir / f"CVE-{year}-0001.json").write_text('{"cveMetadata": {"cveId": "CVE-' + year + '-0001", "state": "PUBLISHED"}, "containers": {"cna": {}}}')

    # Mock datetime to simulate running in 2026
    import cnascorecard_pipeline.ingest as ingest_module

    files = ingest_module._get_cve_file_list(str(tmp_path), None, None)
    # Should find files for current year and previous year
    assert len(files) >= 1, "Should find CVE files for recent years"
```

**Step 2: Run test to verify it fails**

```bash
cd cnascorecard_pipeline && python -m pytest tests/test_ingest.py::test_get_cve_file_list_uses_current_year -v
```

**Step 3: Fix the hardcoded years**

In `cnascorecard_pipeline/ingest.py`, replace lines 98-106:

```python
        # When no date filtering, optimize by only loading recent years
        logger.info("No date filtering - optimizing by loading recent years only")
        recent_years = ['2024', '2025']

        for year in recent_years:
            if (cves_dir / year).exists():
                year_files = _get_year_files(cves_dir, year)
                cve_files.extend(year_files)
                logger.debug(f"Found {len(year_files)} CVE files in {year}")
```

With:

```python
        # When no date filtering, optimize by only loading recent years
        logger.info("No date filtering - optimizing by loading recent years only")
        current_year = datetime.now().year
        recent_years = [str(current_year), str(current_year - 1)]

        for year in recent_years:
            if (cves_dir / year).exists():
                year_files = _get_year_files(cves_dir, year)
                cve_files.extend(year_files)
                logger.debug(f"Found {len(year_files)} CVE files in {year}")
```

**Step 4: Run test to verify it passes**

```bash
cd cnascorecard_pipeline && python -m pytest tests/test_ingest.py::test_get_cve_file_list_uses_current_year -v
```

**Step 5: Commit**

```bash
git add cnascorecard_pipeline/ingest.py cnascorecard_pipeline/tests/test_ingest.py
git commit -m "fix: calculate recent_years dynamically instead of hardcoding 2024/2025"
```

---

## Task 3: Remove Force Push and Harden Workflow

**Files:**
- Modify: `.github/workflows/run-pipeline.yml`

**Step 1: Replace concurrency and remove force push**

Replace the entire workflow with a hardened version that:
- Changes `cancel-in-progress` to `true`
- Splits into `run-pipeline` and `deploy-pages` jobs
- Removes all `git push --force` commands
- Adds job-level timeouts
- Scopes permissions per-job

In `.github/workflows/run-pipeline.yml`, replace the concurrency block (lines 23-25):

```yaml
    concurrency:
      group: "pages"
      cancel-in-progress: false
```

With:

```yaml
    concurrency:
      group: "pipeline"
      cancel-in-progress: true
```

**Step 2: Remove force push fallbacks**

Replace the entire "Commit and Push Changes" step (lines 78-121) with a safer version:

```yaml
    - name: Commit and Push Changes
      run: |
        git config --local user.email "github-actions[bot]@users.noreply.github.com"
        git config --local user.name "github-actions[bot]"
        git add web/
        if git diff --staged --quiet; then
          echo "No changes to commit"
        else
          git commit -m "Automated: Update CNA Scorecard data [skip ci]"

          # Fetch latest and attempt to push
          git fetch origin main

          # Try to push, if it fails attempt rebase
          if ! git push origin HEAD:main; then
            echo "Push failed, attempting to rebase..."
            git pull origin main --rebase || {
              echo "ERROR: Could not rebase. Another workflow may be running."
              echo "This run will be retried on the next scheduled execution."
              exit 1
            }
            git push origin HEAD:main || {
              echo "ERROR: Push failed after rebase. Will retry on next run."
              exit 1
            }
          fi

          echo "Changes pushed successfully"
        fi
```

**Step 3: Add timeout to the job**

Add `timeout-minutes: 30` to the job definition after `runs-on: ubuntu-latest`:

```yaml
  build-and-publish:
    runs-on: ubuntu-latest
    timeout-minutes: 30
```

**Step 4: Commit**

```bash
git add .github/workflows/run-pipeline.yml
git commit -m "fix: remove force push, add cancel-in-progress, add job timeout"
```

---

## Task 4: Add Dependabot Configuration

**Files:**
- Create: `.github/dependabot.yml`

**Step 1: Create Dependabot configuration**

```yaml
version: 2
updates:
  # Python dependencies
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
      - "ci"
```

**Step 2: Commit**

```bash
git add .github/dependabot.yml
git commit -m "feat: add Dependabot for Python and GitHub Actions dependency updates"
```

---

## Task 5: Fix Duplicate Return in Scoring

**Files:**
- Modify: `cnascorecard_pipeline/scoring.py:524-526`

**Step 1: Remove the duplicate return statement**

In `cnascorecard_pipeline/scoring.py`, remove line 526 (the duplicate `return scored_cves`):

Lines 524-526 currently read:
```python
    return scored_cves

    return scored_cves
```

Remove the second `return scored_cves` so it reads:
```python
    return scored_cves
```

**Step 2: Run existing tests**

```bash
cd cnascorecard_pipeline && python -m pytest tests/test_scoring.py -v
```

**Step 3: Commit**

```bash
git add cnascorecard_pipeline/scoring.py
git commit -m "fix: remove dead duplicate return statement in score_multiple_cves"
```

---

## Task 6: Move CWE Regex to Module Level

**Files:**
- Modify: `cnascorecard_pipeline/scoring.py:146-160`

**Step 1: Move regex compilation to module level**

Add at the top of `cnascorecard_pipeline/scoring.py` after the imports (after line 13):

```python
import re

# Pre-compiled patterns for performance (used in hot path)
_CWE_PATTERN = re.compile(r'CWE-\d+', re.IGNORECASE)
```

Then in `_find_valid_cwe()` (lines 156-160), replace:

```python
    import re
    cwe_pattern = re.compile(r'CWE-\d+', re.IGNORECASE)
```

With:

```python
    cwe_pattern = _CWE_PATTERN
```

**Step 2: Do the same in completeness.py**

In `cnascorecard_pipeline/completeness.py`, add at the top after imports (after line 4):

```python
import re

# Pre-compiled patterns for performance
_CWE_PATTERN = re.compile(r'CWE-\d+', re.IGNORECASE)
```

Then in `_custom_check()` around line 158-159, replace:

```python
            import re
            cwe_pattern = re.compile(r'CWE-\d+', re.IGNORECASE)
```

With:

```python
            cwe_pattern = _CWE_PATTERN
```

**Step 3: Run tests**

```bash
cd cnascorecard_pipeline && python -m pytest tests/test_scoring.py tests/test_completeness.py -v
```

**Step 4: Commit**

```bash
git add cnascorecard_pipeline/scoring.py cnascorecard_pipeline/completeness.py
git commit -m "perf: move CWE regex compilation to module level for scoring hot path"
```

---

## Task 7: Fix Duplicated Code in sync_cna_list.py

**Files:**
- Modify: `cnascorecard_pipeline/sync_cna_list.py:35-143`

**Step 1: Fix the duplicated root CNA extraction and enhanced_cna construction**

The `create_enhanced_cna_list` function has duplicated blocks. Lines 51-61 (root CNA extraction) are repeated at lines 85-95. Lines 62-83 build `enhanced_cna` but then lines 96-121 build it again, overwriting the first.

Replace the entire `create_enhanced_cna_list` function body (lines 35-143) with a deduplicated version:

```python
def create_enhanced_cna_list(official_cnas: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Create enhanced CNA list with essential metadata for frontend use."""
    enhanced_cnas = []

    for cna in official_cnas:
        # Robust shortName extraction
        short_name = cna.get('shortName') or cna.get('ShortName') or cna.get('cnaShortName')
        if not short_name:
            if 'organizationName' in cna:
                short_name = cna['organizationName'].replace(' ', '_').lower()
            elif 'cnaID' in cna:
                short_name = cna['cnaID']
            else:
                logging.warning(f"Skipping CNA with no shortName or fallback: {cna}")
                continue

        # Extract root CNA info (single extraction, no duplication)
        root_cna_info = {}
        if 'CNA' in cna and 'root' in cna['CNA']:
            if cna['CNA']['root'].get('shortName', '').lower() != 'n/a':
                root_cna_info = cna['CNA']['root']
            elif 'rootCnaInfo' in cna:
                root_cna_info = cna['rootCnaInfo']
        elif 'rootCnaInfo' in cna:
            root_cna_info = cna['rootCnaInfo']

        # Robustly extract cnaID and type (single extraction, no duplication)
        cna_id = ''
        cna_types = []
        if 'CNA' in cna:
            cna_id = cna['CNA'].get('cnaID', '') or cna.get('cnaID', '')
            cna_types = cna['CNA'].get('type', [])
        else:
            cna_id = cna.get('cnaID', '')
            cna_types = cna.get('type', [])

        # Ensure cna_types is always a list
        if isinstance(cna_types, str):
            cna_types = [cna_types]
        elif not isinstance(cna_types, list):
            cna_types = []

        # Build enhanced CNA entry (single construction)
        enhanced_cna = {
            'shortName': short_name,
            'organizationName': cna.get('organizationName', short_name),
            'scope': cna.get('scope', ''),
            'cnaID': cna_id,
            'type': cna_types,
            'advisories': [],
            'email': [],
            'country': cna.get('country', ''),
            'disclosurePolicy': cna.get('disclosurePolicy', []),
            'rootCnaInfo': root_cna_info
        }

        # Extract CNA type from nested structure
        if 'CNA' in cna and 'type' in cna['CNA']:
            enhanced_cna['type'] = cna['CNA']['type']

        # Extract advisories
        if 'securityAdvisories' in cna and 'advisories' in cna['securityAdvisories']:
            enhanced_cna['advisories'] = cna['securityAdvisories']['advisories']

        # Extract email contacts
        if 'contact' in cna:
            for contact in cna['contact']:
                if 'email' in contact:
                    enhanced_cna['email'].extend(contact['email'])

        enhanced_cnas.append(enhanced_cna)

    # Sort by organization name for consistent ordering
    enhanced_cnas.sort(key=lambda x: x['organizationName'].lower())

    logging.info(f"Created enhanced CNA list with {len(enhanced_cnas)} entries")
    return enhanced_cnas
```

**Step 2: Run pipeline to verify**

```bash
cd cnascorecard_pipeline && python -c "from sync_cna_list import create_enhanced_cna_list; print('Import OK')"
```

**Step 3: Commit**

```bash
git add cnascorecard_pipeline/sync_cna_list.py
git commit -m "refactor: deduplicate root CNA extraction and enhanced_cna construction in sync_cna_list"
```

---

## Task 8: Replace Print Statements with Logging in Aggregation

**Files:**
- Modify: `cnascorecard_pipeline/aggregation.py`

**Step 1: Add logger and replace all print statements**

Add logging import and logger at the top of `aggregation.py` (after the existing imports, line 7):

```python
import logging

logger = logging.getLogger('cnascorecard.aggregation')
```

Then replace all `print()` calls throughout the file:

- Line 56: `print(f"[WARNING] Error reading CNA metadata file: {e}")` → `logger.warning(f"Error reading CNA metadata file: {e}")`
- Line 59: `print(f"[DEBUG] Loaded {len(official_cna_names)} official CNAs from metadata")` → `logger.debug(f"Loaded {len(official_cna_names)} official CNAs from metadata")`
- Line 60: `print(f"[DEBUG] Found CVE data for {len(cna_cves)} CNAs")` → `logger.debug(f"Found CVE data for {len(cna_cves)} CNAs")`
- Line 104: `print(f"[DEBUG] Mapped CVE data to {len(official_cna_cves)} official CNAs")` → `logger.debug(f"Mapped CVE data to {len(official_cna_cves)} official CNAs")`
- Lines 105-108: Replace print block with logger.debug calls
- Line 226 (Fortinet debug): `print(f"[DEBUG] Fortinet patchinfo avg: ...")` → `logger.debug(f"Fortinet patchinfo avg: ...")`

**Step 2: Run tests**

```bash
cd cnascorecard_pipeline && python -m pytest tests/test_aggregation.py -v
```

**Step 3: Commit**

```bash
git add cnascorecard_pipeline/aggregation.py
git commit -m "refactor: replace print statements with proper logging in aggregation module"
```

---

## Task 9: Fix Memory Double-Load in Pipeline

**Files:**
- Modify: `cnascorecard_pipeline/pipeline.py:201-215`

**Step 1: Refactor _load_cve_data to load once and filter in-memory**

Replace `_load_cve_data()` method (lines 201-218):

```python
    def _load_cve_data(self) -> None:
        """Load CVE data for analysis (full mode)."""
        self.logger.info("Loading CVE data (full mode)")

        # Load all CVE records once (needed for trend analysis)
        self.cve_records = load_cve_records()
        self.logger.info(f"Loaded {len(self.cve_records)} total CVE records")

        # Filter in-memory for current analysis period instead of re-loading from disk
        current_start, current_end = self.analysis_periods['current']
        start_dt = datetime.strptime(current_start, "%Y-%m-%d")
        end_dt = datetime.strptime(current_end, "%Y-%m-%d")

        self.filtered_cve_records = []
        for cve in self.cve_records:
            date_str = cve.get("cveMetadata", {}).get("datePublished", "")
            if not date_str:
                continue
            try:
                pub_date = datetime.strptime(date_str[:10], "%Y-%m-%d")
                if start_dt <= pub_date <= end_dt:
                    self.filtered_cve_records.append(cve)
            except ValueError:
                continue

        self.logger.info(f"Filtered to {len(self.filtered_cve_records)} CVE records for current period")

        if not self.filtered_cve_records:
            raise PipelineError("No CVE records found for the specified analysis period")
```

**Step 2: Run pipeline tests**

```bash
cd cnascorecard_pipeline && python -m pytest tests/test_pipeline.py -v
```

**Step 3: Commit**

```bash
git add cnascorecard_pipeline/pipeline.py
git commit -m "perf: load CVE data once and filter in-memory instead of double-loading from disk"
```

---

## Task 10: Add Type Hints to Aggregation Module

**Files:**
- Modify: `cnascorecard_pipeline/aggregation.py`

**Step 1: Add type hints to all functions**

The `aggregate_cna_scores` function already has basic hints. Add hints to the nested functions and local variables:

- `map_cve_name_to_official(cve_name: str, official_names: set, metadata_map: Dict[str, Any]) -> Optional[str]`
- `calculate_monthly_trend(cves: List[Dict], months: int = 6) -> List`
- `summarize_trend(monthly_trends: List) -> Dict[str, str]`

Also add `Optional` to the imports at the top:

```python
from typing import List, Dict, Tuple, Any, Optional
```

**Step 2: Run mypy**

```bash
cd cnascorecard_pipeline && python -m mypy aggregation.py --ignore-missing-imports
```

**Step 3: Commit**

```bash
git add cnascorecard_pipeline/aggregation.py
git commit -m "refactor: add type hints to aggregation module"
```

---

## Task 11: Add Type Hints to Completeness Module

**Files:**
- Modify: `cnascorecard_pipeline/completeness.py`

**Step 1: Add type hints to public functions**

Update function signatures:

- `compute_field_utilization(cve_records: List[Dict[str, Any]], field_list: List[str]) -> List[Dict[str, Any]]`
- `compute_individual_cna_field_utilization(cve_records: List[Dict[str, Any]], field_list: List[str]) -> Dict[str, List[Dict[str, Any]]]`
- `_get_nested_value(data: Dict[str, Any], path: List[str]) -> Any`
- `_custom_check(data: Any, check_type: str) -> bool`
- `_get_schema_fields() -> Dict[str, Dict[str, Any]]`

**Step 2: Run mypy**

```bash
cd cnascorecard_pipeline && python -m mypy completeness.py --ignore-missing-imports
```

**Step 3: Commit**

```bash
git add cnascorecard_pipeline/completeness.py
git commit -m "refactor: add type hints to completeness module"
```

---

## Task 12: Fix Error Handling in Ingest Batch Loading

**Files:**
- Modify: `cnascorecard_pipeline/ingest.py:336-338`

**Step 1: Replace bare except with proper logging**

In `_load_cve_batch()`, replace lines 336-338:

```python
        except Exception:
            failed += 1
```

With:

```python
        except Exception as e:
            failed += 1
            # Log only at trace level to avoid flooding logs during batch processing
            if failed <= 5:  # Log first few failures for diagnostics
                import logging
                logging.getLogger('cnascorecard.ingest').debug(
                    f"Failed to load CVE file {file_path}: {type(e).__name__}: {e}"
                )
```

**Step 2: Run tests**

```bash
cd cnascorecard_pipeline && python -m pytest tests/test_ingest.py -v
```

**Step 3: Commit**

```bash
git add cnascorecard_pipeline/ingest.py
git commit -m "fix: add diagnostic logging for batch CVE loading failures instead of bare except"
```

---

## Task 13: Add Retry Logic to CNA List Download

**Files:**
- Modify: `cnascorecard_pipeline/sync_cna_list.py:14-29`

**Step 1: Add retry with backoff**

Replace `download_official_cnas_list()` function:

```python
def download_official_cnas_list() -> List[Dict[str, Any]]:
    """Download the official CNAs list from CVE Project GitHub repository."""
    url = "https://raw.githubusercontent.com/CVEProject/cve-website/dev/src/assets/data/CNAsList.json"

    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            logging.info(f"Downloading official CNAs list from: {url} (attempt {attempt + 1})")
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            data = response.json()
            logging.info(f"Successfully downloaded {len(data)} CNAs from official list")
            return data

        except requests.RequestException as e:
            if attempt < max_retries:
                import time
                wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s
                logging.warning(f"Download attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
            else:
                logging.error(f"Failed to download CNAs list after {max_retries + 1} attempts: {e}")
                raise
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse CNAs list JSON: {e}")
            raise
```

**Step 2: Commit**

```bash
git add cnascorecard_pipeline/sync_cna_list.py
git commit -m "feat: add retry with exponential backoff for CNA list download"
```

---

## Task 14: Create Shared CSS for Pagination

**Files:**
- Create: `web/shared/pagination.css`
- Modify: `web/leaderboard.css` (remove pagination rules)
- Modify: `web/cna/pagination.css` (remove duplicated rules)
- Modify: `web/cna/cna-detail.css` (remove pagination rules)
- Modify: `web/cna/cna-index.css` (remove pagination rules)
- Modify: HTML files to include shared pagination CSS

**Step 1: Create shared pagination CSS**

Create `web/shared/pagination.css` with the canonical pagination styles extracted from the 4 files. Use the most complete version (from `cna/cna-index.css`) as the base:

```css
/* Shared Pagination Styles */
.pagination-controls {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  margin-top: 1.5rem;
  padding: 1rem 0;
}

.pagination-button {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 0.5rem 0.75rem;
  border: 1px solid var(--color-border, #d1d5db);
  border-radius: 6px;
  background: var(--color-bg, #fff);
  color: var(--color-text, #374151);
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s ease;
  min-width: 36px;
  height: 36px;
}

.pagination-button:hover:not(:disabled) {
  background: var(--color-primary, #0066cc);
  color: #fff;
  border-color: var(--color-primary, #0066cc);
}

.pagination-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.page-number {
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 36px;
  height: 36px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s ease;
  border: 1px solid transparent;
}

.page-number:hover {
  background: var(--color-bg-secondary, #f3f4f6);
}

.page-number.active {
  background: var(--color-primary, #0066cc);
  color: #fff;
  font-weight: 600;
}

.page-ellipsis {
  display: flex;
  align-items: center;
  justify-content: center;
  min-width: 36px;
  height: 36px;
  color: var(--color-text-secondary, #6b7280);
}

.pagination-info {
  font-size: 0.875rem;
  color: var(--color-text-secondary, #6b7280);
  text-align: center;
  margin-bottom: 0.5rem;
}
```

**Step 2: Remove duplicated pagination rules from other CSS files**

Remove the pagination-related CSS blocks from:
- `web/leaderboard.css`
- `web/cna/pagination.css` (can be deleted entirely if only pagination)
- `web/cna/cna-detail.css`
- `web/cna/cna-index.css`

**Step 3: Add shared pagination CSS to HTML files**

Add `<link rel="stylesheet" href="../shared/pagination.css">` (or appropriate relative path) to:
- `web/cna/index.html`
- `web/cna/cna-detail.html`
- `web/completeness/index.html`

And `<link rel="stylesheet" href="shared/pagination.css">` to pages at the web root level.

**Step 4: Test visually**

Open each page and verify pagination looks correct.

**Step 5: Commit**

```bash
git add web/shared/pagination.css web/leaderboard.css web/cna/pagination.css web/cna/cna-detail.css web/cna/cna-index.css web/cna/index.html web/cna/cna-detail.html web/completeness/index.html
git commit -m "refactor: extract shared pagination CSS, remove duplication across 4 files"
```

---

## Task 15: Create Shared JavaScript Utilities

**Files:**
- Create: `web/shared/utils.js`
- Modify: `web/leaderboard.js` (use shared utils)
- Modify: `web/cna/cna-index.js` (use shared utils)

**Step 1: Create shared utility module**

Create `web/shared/utils.js`:

```javascript
/**
 * Shared utilities for CNA Scorecard web pages.
 * Include this script before page-specific scripts.
 */

const ScoreCardUtils = {
  /**
   * Calculate letter grade from numerical score.
   * @param {number} score - Score from 0-100
   * @returns {string} Letter grade
   */
  getGrade(score) {
    if (score >= 95) return 'A+';
    if (score >= 90) return 'A';
    if (score >= 85) return 'B+';
    if (score >= 80) return 'B';
    if (score >= 75) return 'C+';
    if (score >= 70) return 'C';
    if (score >= 65) return 'D+';
    if (score >= 60) return 'D';
    return 'F';
  },

  /**
   * Get CSS color class for a grade.
   * @param {string} grade - Letter grade
   * @returns {string} CSS class name
   */
  getGradeColorClass(grade) {
    if (grade.startsWith('A')) return 'grade-excellent';
    if (grade.startsWith('B')) return 'grade-good';
    if (grade.startsWith('C')) return 'grade-average';
    if (grade.startsWith('D')) return 'grade-poor';
    return 'grade-failing';
  },

  /**
   * Format a date string for display.
   * @param {string} dateStr - ISO date string
   * @returns {string} Formatted date
   */
  formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    try {
      const date = new Date(dateStr);
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    } catch {
      return dateStr;
    }
  },

  /**
   * Format a number with commas.
   * @param {number} n - Number to format
   * @returns {string} Formatted number
   */
  formatNumber(n) {
    if (n === null || n === undefined) return '0';
    return n.toLocaleString();
  },

  /**
   * Debounce a function.
   * @param {Function} func - Function to debounce
   * @param {number} wait - Milliseconds to wait
   * @returns {Function} Debounced function
   */
  debounce(func, wait) {
    let timeout;
    return function(...args) {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  },

  /**
   * Sanitize a string for safe HTML insertion (prevent XSS).
   * @param {string} str - String to sanitize
   * @returns {string} Sanitized string
   */
  sanitizeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  },

  /**
   * Sanitize a URL parameter value.
   * @param {string} param - URL parameter value
   * @returns {string} Sanitized parameter
   */
  sanitizeParam(param) {
    if (!param) return '';
    // Allow alphanumeric, hyphens, underscores, dots, and spaces
    return param.replace(/[^a-zA-Z0-9\-_.@ ]/g, '');
  },

  /**
   * Format score with visual bar HTML.
   * @param {number} score - Score value
   * @param {boolean} isPercentage - Whether score is a percentage
   * @returns {string} HTML string
   */
  formatScoreWithBar(score, isPercentage = false) {
    const value = score || 0;
    const percentage = isPercentage ? value : Math.min(100, (value / 100) * 100);
    let colorClass = 'score-low';

    if (percentage >= 80) colorClass = 'score-great';
    else if (percentage >= 60) colorClass = 'score-good';
    else if (percentage >= 40) colorClass = 'score-medium';

    const displayValue = isPercentage ? `${value.toFixed(1)}%` : value.toFixed(1);

    return `
      <div class="score-display">
        <div class="score-value">${displayValue}</div>
        <div class="score-bar">
          <div class="score-fill ${colorClass}" style="width: ${percentage}%"></div>
        </div>
      </div>
    `;
  }
};
```

**Step 2: Include in HTML pages**

Add `<script src="../shared/utils.js"></script>` (or appropriate path) before page-specific scripts in:
- `web/cna/index.html`
- `web/cna/cna-detail.html`
- `web/completeness/index.html`
- `web/index.html`

**Step 3: Update cna-index.js to use shared utilities**

Replace the local `formatScoreWithBar` function (lines 424-447 of `cna-index.js`) and `debounce` function (lines 657-663) with references to `ScoreCardUtils.formatScoreWithBar` and `ScoreCardUtils.debounce`.

**Step 4: Commit**

```bash
git add web/shared/utils.js web/cna/index.html web/cna/cna-detail.html web/completeness/index.html web/index.html web/cna/cna-index.js
git commit -m "feat: create shared JS utilities module, reduce duplication across pages"
```

---

## Task 16: Remove Console.log from Production Code

**Files:**
- Modify: `web/cna/cna-detail.js`
- Modify: `web/cna/cna-index.js`
- Modify: `web/leaderboard.js`

**Step 1: Remove console.log statements**

Search all JS files for `console.log` and remove debug logging. Keep `console.error` for actual error conditions.

Key files:
- `web/cna/cna-detail.js`: Remove extensive debug logging
- `web/cna/cna-index.js`: Remove lines 66-69 console.log calls
- `web/leaderboard.js`: Remove line 72 `console.log`

**Step 2: Commit**

```bash
git add web/cna/cna-detail.js web/cna/cna-index.js web/leaderboard.js
git commit -m "cleanup: remove console.log debug statements from production JS"
```

---

## Task 17: Add Input Sanitization for URL Parameters

**Files:**
- Modify: `web/cna/cna-detail.js`

**Step 1: Sanitize the shortName URL parameter**

The CNA detail page reads `?shortName=` from the URL without validation. Find where it parses the URL parameter and add sanitization:

```javascript
// Before (unsafe):
const urlParams = new URLSearchParams(window.location.search);
const shortName = urlParams.get('shortName');

// After (safe):
const urlParams = new URLSearchParams(window.location.search);
const rawShortName = urlParams.get('shortName');
const shortName = rawShortName ? ScoreCardUtils.sanitizeParam(rawShortName) : null;
```

Ensure this is done before the parameter is used in any DOM insertion or fetch URL construction.

**Step 2: Commit**

```bash
git add web/cna/cna-detail.js
git commit -m "security: sanitize URL parameters to prevent XSS on CNA detail page"
```

---

## Task 18: Fix CSS Color Inconsistencies

**Files:**
- Modify: `web/assets/theme.css`
- Modify: `web/leaderboard.js` (hardcoded color)

**Step 1: Audit and fix color references**

In `web/assets/theme.css`, ensure these CSS variables exist:

```css
:root {
  --color-border: #d1d5db;
  --color-border-light: #e5e7eb;
}
```

Search for hardcoded color `#0074d9` across JS files and replace with `var(--color-primary)` where used in CSS, or ensure consistency.

In `web/leaderboard.js` line 233, the hardcoded `color:#0074d9` should use the CSS variable instead.

**Step 2: Commit**

```bash
git add web/assets/theme.css web/leaderboard.js
git commit -m "fix: standardize color values using CSS variables from theme.css"
```

---

## Task 19: Add Meta Tags for SEO

**Files:**
- Modify: `web/index.html`
- Modify: `web/cna/index.html`
- Modify: `web/completeness/index.html`
- Modify: `web/scoring.html`
- Modify: `web/trends.html`
- Modify: `web/badges.html`

**Step 1: Add meta description and Open Graph tags to each page**

For each HTML file, add inside `<head>`:

**web/index.html:**
```html
<meta name="description" content="CNA Scorecard measures CVE data quality across 300+ CVE Numbering Authorities with transparent scoring and rankings.">
<meta property="og:title" content="CNA Scorecard - CVE Data Quality Dashboard">
<meta property="og:description" content="Transparent, data-driven insights into CVE data quality across 300+ CNAs.">
<meta property="og:type" content="website">
<link rel="canonical" href="https://cnascorecard.org/">
```

**web/cna/index.html:**
```html
<meta name="description" content="Browse and compare CNA performance rankings. Search, sort, and filter 300+ CVE Numbering Authorities by data quality scores.">
<link rel="canonical" href="https://cnascorecard.org/cna/">
```

**web/scoring.html:**
```html
<meta name="description" content="Learn how CNA Scorecard scores CVE records across 5 categories: completeness, root cause, severity, software identification, and patch info.">
<link rel="canonical" href="https://cnascorecard.org/scoring.html">
```

**web/trends.html:**
```html
<meta name="description" content="Track CVE data quality trends over time with rolling 7-day averages and identify top-improving CNAs.">
<link rel="canonical" href="https://cnascorecard.org/trends.html">
```

**web/completeness/index.html:**
```html
<meta name="description" content="Analyze CVE schema field utilization across all CNAs. See which fields are most and least populated.">
<link rel="canonical" href="https://cnascorecard.org/completeness/">
```

**web/badges.html:**
```html
<meta name="description" content="Generate embeddable SVG badges showing your CNA's scorecard rating and rank.">
<link rel="canonical" href="https://cnascorecard.org/badges.html">
```

**Step 2: Commit**

```bash
git add web/index.html web/cna/index.html web/completeness/index.html web/scoring.html web/trends.html web/badges.html
git commit -m "feat: add meta descriptions, canonical links, and Open Graph tags for SEO"
```

---

## Task 20: Add ARIA Live Regions for Dynamic Content

**Files:**
- Modify: `web/cna/index.html`
- Modify: `web/cna/cna-index.js`

**Step 1: Add aria-live regions to HTML**

In `web/cna/index.html`, add `aria-live="polite"` to the table body and pagination info:

```html
<div class="pagination-info" aria-live="polite">
  Showing <span id="startIndex">1</span>-<span id="endIndex">25</span> of <span id="totalItems">0</span> CNAs
</div>
```

And on the table:
```html
<tbody aria-live="polite" aria-atomic="false">
```

**Step 2: Commit**

```bash
git add web/cna/index.html
git commit -m "a11y: add aria-live regions for dynamic table and pagination updates"
```

---

## Task 21: Add Aggregation Tests

**Files:**
- Modify: `cnascorecard_pipeline/tests/test_aggregation.py`

**Step 1: Write comprehensive aggregation tests**

Add the following tests to `cnascorecard_pipeline/tests/test_aggregation.py`:

```python
"""Tests for aggregation module."""
import pytest
import json
import os
from unittest.mock import patch, mock_open
from datetime import datetime
from aggregation import aggregate_cna_scores


def _make_scored_cve(cve_id, cna_name, total_score, breakdown=None):
    """Helper to create a scored CVE dict."""
    if breakdown is None:
        breakdown = {
            'foundationalCompleteness': 50,
            'rootCauseAnalysis': 15,
            'severityAndImpactContext': 15,
            'softwareIdentification': 10,
            'patchinfo': 10
        }
    return {
        'cveId': cve_id,
        'assigningCna': cna_name,
        'datePublished': '2026-01-15',
        'totalScore': total_score,
        'scoreBreakdown': breakdown,
        'recent': True
    }


def test_aggregate_empty_input():
    """aggregate_cna_scores should handle empty input gracefully."""
    periods = [
        (datetime(2025, 9, 1), datetime(2026, 3, 1)),
        (datetime(2025, 3, 1), datetime(2025, 8, 31))
    ]
    # Mock the CNA list file to not exist
    with patch('os.path.exists', return_value=False):
        result = aggregate_cna_scores([], periods)
    assert isinstance(result, dict)


def test_aggregate_groups_by_cna():
    """Scores should be grouped by CNA name."""
    scored = [
        _make_scored_cve('CVE-2026-0001', 'TestCNA', 80),
        _make_scored_cve('CVE-2026-0002', 'TestCNA', 90),
        _make_scored_cve('CVE-2026-0003', 'OtherCNA', 70),
    ]
    periods = [
        (datetime(2025, 9, 1), datetime(2026, 3, 1)),
        (datetime(2025, 3, 1), datetime(2025, 8, 31))
    ]
    # Mock CNA list with matching names
    mock_cna_list = [
        {'shortName': 'TestCNA', 'organizationName': 'Test CNA Org'},
        {'shortName': 'OtherCNA', 'organizationName': 'Other CNA Org'}
    ]
    with patch('builtins.open', mock_open(read_data=json.dumps(mock_cna_list))):
        with patch('os.path.exists', return_value=True):
            result = aggregate_cna_scores(scored, periods)

    assert 'TestCNA' in result
    assert 'OtherCNA' in result


def test_aggregate_calculates_average():
    """Average score should be calculated correctly."""
    scored = [
        _make_scored_cve('CVE-2026-0001', 'TestCNA', 80),
        _make_scored_cve('CVE-2026-0002', 'TestCNA', 60),
    ]
    periods = [
        (datetime(2025, 9, 1), datetime(2026, 3, 1)),
        (datetime(2025, 3, 1), datetime(2025, 8, 31))
    ]
    mock_cna_list = [{'shortName': 'TestCNA', 'organizationName': 'Test'}]
    with patch('builtins.open', mock_open(read_data=json.dumps(mock_cna_list))):
        with patch('os.path.exists', return_value=True):
            result = aggregate_cna_scores(scored, periods)

    cna_scoring = result['TestCNA']['cna_scoring'][0]
    assert cna_scoring['overall_average_score'] == 70.0
```

**Step 2: Run tests**

```bash
cd cnascorecard_pipeline && python -m pytest tests/test_aggregation.py -v
```

**Step 3: Commit**

```bash
git add cnascorecard_pipeline/tests/test_aggregation.py
git commit -m "test: add comprehensive aggregation tests for grouping, averaging, and edge cases"
```

---

## Task 22: Move Misplaced Test File

**Files:**
- Move: `cnascorecard_pipeline/test_cpe_applicability.py` → `cnascorecard_pipeline/tests/test_cpe_applicability.py`

**Step 1: Move the test file**

```bash
mv cnascorecard_pipeline/test_cpe_applicability.py cnascorecard_pipeline/tests/test_cpe_applicability.py
```

**Step 2: Run to verify it still works**

```bash
cd cnascorecard_pipeline && python -m pytest tests/test_cpe_applicability.py -v
```

**Step 3: Commit**

```bash
git add cnascorecard_pipeline/tests/test_cpe_applicability.py
git rm cnascorecard_pipeline/test_cpe_applicability.py
git commit -m "chore: move test_cpe_applicability.py to tests/ directory"
```

---

## Task 23: Add Workflow Output Validation

**Files:**
- Modify: `.github/workflows/run-pipeline.yml`

**Step 1: Add a validation step after pipeline run**

Add a new step after "Run the Data Pipeline" and before "Commit and Push Changes":

```yaml
    - name: Validate pipeline output
      run: |
        echo "Validating pipeline output..."

        # Check that critical output files exist
        for file in web/data/cna_combined.json web/data/field_utilization.json web/data/performance_trends.json; do
          if [ ! -f "$file" ]; then
            echo "ERROR: Missing expected output file: $file"
            exit 1
          fi
          # Validate JSON syntax
          python -c "import json; json.load(open('$file'))" || {
            echo "ERROR: Invalid JSON in $file"
            exit 1
          }
        done

        echo "All output files validated successfully"
```

**Step 2: Commit**

```bash
git add .github/workflows/run-pipeline.yml
git commit -m "feat: add output validation step to verify pipeline produces valid JSON"
```

---

## Task 24: Fix Double-Fetch on Homepage

**Files:**
- Modify: `web/index.html` (or the JS that loads data)

**Step 1: Identify and fix the double fetch**

Examine the homepage JavaScript to find where `cna_combined.json` is fetched twice. Store the result of the first fetch and reuse it instead of fetching again.

**Step 2: Commit**

```bash
git add web/index.html
git commit -m "perf: fix double-fetch of cna_combined.json on homepage"
```

---

## Summary

| Task | Type | Area | Description |
|------|------|------|-------------|
| 1 | Bug fix | CI/CD | Fix broken cache key |
| 2 | Bug fix | Pipeline | Fix hardcoded year |
| 3 | Security | CI/CD | Remove force push |
| 4 | Feature | CI/CD | Add Dependabot |
| 5 | Bug fix | Pipeline | Remove dead code |
| 6 | Perf | Pipeline | Module-level regex |
| 7 | Refactor | Pipeline | Dedup sync_cna_list |
| 8 | Refactor | Pipeline | Logging in aggregation |
| 9 | Perf | Pipeline | Fix memory double-load |
| 10 | Refactor | Pipeline | Type hints - aggregation |
| 11 | Refactor | Pipeline | Type hints - completeness |
| 12 | Bug fix | Pipeline | Error handling in ingest |
| 13 | Feature | Pipeline | Retry logic for downloads |
| 14 | Refactor | Web | Shared pagination CSS |
| 15 | Feature | Web | Shared JS utilities |
| 16 | Cleanup | Web | Remove console.log |
| 17 | Security | Web | Sanitize URL params |
| 18 | Bug fix | Web | Fix color inconsistencies |
| 19 | Feature | Web | SEO meta tags |
| 20 | A11y | Web | ARIA live regions |
| 21 | Test | Pipeline | Aggregation tests |
| 22 | Chore | Pipeline | Move misplaced test |
| 23 | Feature | CI/CD | Output validation |
| 24 | Perf | Web | Fix double-fetch |
