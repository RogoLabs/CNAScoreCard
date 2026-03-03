# CNA Scorecard March 2026 Improvement Plan

**Date:** 2026-03-03
**Branch:** MarchUpdate
**Approach:** Bottom-up (infrastructure first), single comprehensive plan

## Overview

A comprehensive improvement plan based on a deep dive of the entire codebase covering the Python pipeline, web frontend, and GitHub Actions. Organized into 4 sections executed in dependency order.

---

## Section 1: Critical Bugs & CI/CD Hardening

### 1.1 Fix Broken CVE Data Cache Key
- **File:** `.github/workflows/run-pipeline.yml`
- **Bug:** Cache key `cve-data-${{ github.run_number }}` creates a new cache entry every run, so CVE data is re-downloaded from scratch every 6 hours
- **Fix:** Change to `cve-data-v1` with `restore-keys: cve-data-` so the cache persists across runs
- **Impact:** Saves ~5-10 minutes per pipeline run

### 1.2 Fix Hardcoded Year Bug
- **File:** `cnascorecard_pipeline/ingest.py` (~line 100)
- **Bug:** `recent_years = ['2024', '2025']` will miss 2026+ CVEs
- **Fix:** Calculate dynamically from current year: `[str(datetime.now().year), str(datetime.now().year - 1)]`
- **Impact:** Pipeline will stop ingesting new CVEs without this fix

### 1.3 Remove Force Push from Workflow
- **File:** `.github/workflows/run-pipeline.yml`
- **Problem:** Two `git push --force` commands that could corrupt repository history
- **Fix:** Change concurrency to `cancel-in-progress: true` and remove force push fallback. If push fails after merge attempt, fail the workflow cleanly.
- **Impact:** Eliminates risk of repository history corruption

### 1.4 Split Workflow into Jobs
- **Current:** Single monolithic `build-and-publish` job
- **Change:** Split into 2 jobs:
  - `run-pipeline`: checkout, install, run pipeline, commit/push
  - `deploy-pages`: depends on run-pipeline, deploys to GitHub Pages
- **Benefit:** Clearer separation of concerns, can re-run deploy independently

### 1.5 Add Security Scanning & Dependabot
- Add `.github/dependabot.yml` for Python deps and GitHub Actions version updates
- Add `pip-audit` step to workflow to catch vulnerable dependencies
- Add job-level timeout (30 min) and step-level timeouts (10 min)

### 1.6 Tighten Workflow Permissions
- Scope permissions per-job instead of workflow-level
- Pipeline job: `contents: write` only
- Deploy job: `pages: write` + `id-token: write` only

---

## Section 2: Python Pipeline Refactoring

### 2.1 Eliminate Code Duplication

**2.1a - CNA Name Mapping (`sync_cna_list.py`)**
- Lines 51-61 and 85-95 contain identical root CNA extraction logic
- Extract into single reusable function

**2.1b - Field Utilization Logic (`completeness.py`)**
- `compute_field_utilization()` and `compute_individual_cna_field_utilization()` share ~80 lines of identical logic
- Extract shared logic into a helper parameterized by scope (global vs per-CNA)

**2.1c - Scoring Config Instances**
- `scoring.py`, `trends.py`, and `aggregation.py` each create/load their own config
- Consolidate to a single shared instance passed through the pipeline

### 2.2 Add Type Hints
- `aggregation.py` - zero type hints, add to all functions
- `completeness.py` - zero type hints, add to all functions
- `scoring.py` - partial coverage, complete all public function signatures
- `trends.py` - partial coverage, complete all public function signatures
- Tighten mypy config: remove `no_strict_optional = true`, add `warn_return_any = true`

### 2.3 Fix Error Handling
- `ingest.py` line 336-339: bare `except Exception` with `pass` - add proper logging
- `aggregation.py` lines 55-57: silently continues on missing metadata - log and use explicit defaults
- `scoring.py` line 525-526: duplicate return statement (dead code) - remove
- `sync_cna_list.py`: add retry logic (1 retry with backoff) for network requests
- `pipeline.py`: validate CVE data loaded successfully before scoring

### 2.4 Performance Fixes

**2.4a - Regex Compilation**
- `scoring.py` line ~159: CWE regex pattern compiled inside loop for every CVE
- Move to module-level constant

**2.4b - Trends Re-scoring**
- `trends.py` re-scores every CVE during trend calculation
- Pass pre-scored data to trends instead of raw CVEs

**2.4c - Memory Efficiency**
- `pipeline.py` loads all CVE records then loads filtered records separately (two full loads)
- Load once, filter in-memory

### 2.5 Replace Print Statements with Logging
- `aggregation.py`: replace all `print()` debug statements with `logger.debug()`
- Ensure consistent `logging` module usage throughout all modules

### 2.6 Fix Naming Inconsistencies
- Category keys vary across modules (camelCase in scoring, snake_case in trends)
- Define category name constants in `config.py` and reference them everywhere

---

## Section 3: Web Frontend Improvements

### 3.1 CSS Consolidation

**3.1a - Shared Pagination Component**
- Pagination styles duplicated in 4 files: `leaderboard.css`, `cna/pagination.css`, `cna/cna-detail.css`, `cna/cna-index.css`
- Extract into `shared/pagination.css`
- Remove duplicated rules from all 4 files

**3.1b - Shared Table Styles**
- Table styling scattered across `leaderboard.css`, `cna-index.css`, `completeness.css`
- Extract common table styles into `shared/shared.css`
- Keep only page-specific overrides in individual files

**3.1c - Fix Color Inconsistencies**
- Primary color `#0066cc` in theme.css but `#0074d9` used elsewhere
- Border colors vary: `#e0e0e0`, `#d1d5db`, `#f0f0f0` used inconsistently
- Audit all hardcoded colors and replace with CSS variables from `theme.css`

**3.1d - Consistent Breakpoints**
- Currently 768px, 900px, 1024px, 1200px used inconsistently
- Standardize on documented breakpoint system

### 3.2 JavaScript Shared Utilities

**3.2a - Create `shared/utils.js`**
- Extract duplicated functions: `getGrade()`, `getGradeColor()`, `formatDate()`, `formatNumber()`, `debounce()`, `sanitizeInput()`

**3.2b - Create `shared/pagination.js`**
- Extract pagination logic from `cna-index.js`, `leaderboard.js`, `completeness.js`
- Generic component: data array + page size + render callback

**3.2c - Create `shared/sorting.js`**
- Extract table sorting logic duplicated in 3+ files
- Generic sort with column config and direction toggle

**3.2d - Remove Console.log Statements**
- `cna-detail.js` has extensive debug logging in production
- Remove all console.log from production code

### 3.3 Accessibility Improvements
- Add missing ARIA labels on interactive elements
- Add `aria-live="polite"` regions for dynamic content updates
- Ensure grade badges have text content (not color-only)
- Add keyboard navigation for pagination controls
- Add proper `role` attributes to custom table components

### 3.4 SEO & Meta Tags
- Add `<meta name="description">` to all pages
- Add Open Graph tags to pages missing them
- Add Twitter card meta tags
- Add canonical link tags
- Add `sitemap.xml`

### 3.5 Performance Quick Wins
- Fix double-fetch of `cna_combined.json` on homepage
- Add `loading="lazy"` to images
- Ensure Chart.js has `defer` attribute
- Add resize debounce for chart re-rendering

### 3.6 Input Validation & Security
- Sanitize URL query parameters (`?cna=` parameter on detail page)
- Sanitize search input to prevent XSS

---

## Section 4: Testing & Observability

### 4.1 Fill Python Test Coverage Gaps

**4.1a - Aggregation Tests**
- `aggregate_cna_scores()` has no tests
- Add tests for: basic aggregation, CNA name mapping (4 fallback strategies), edge cases (unknown CNA, empty input)

**4.1b - Completeness Tests**
- Individual CNA field utilization has minimal testing
- Add tests for `_custom_check()` function
- Add edge case tests for empty fields, partial data

**4.1c - Integration Test**
- No end-to-end test exists
- Add lightweight integration test with small fixture dataset (~10 CVEs)
- Validates: ingest → score → aggregate → output JSON structure

### 4.2 Fix Existing Test Issues
- Move `test_cpe_applicability.py` from pipeline root to `tests/` directory
- Ensure all tests run with `pytest` from project root

### 4.3 Add Workflow Health Checks
- Validate output JSON files exist and are valid after pipeline run
- Verify GitHub Pages URL returns 200 post-deployment
- Log pipeline runtime for performance tracking

### 4.4 Add Pre-commit to CI
- Project has `.pre-commit-config.yaml` but not enforced in CI
- Add CI step running pre-commit checks on PRs

---

## Summary

| Section | Items | Sub-items | Scope |
|---------|-------|-----------|-------|
| 1. Critical Bugs & CI/CD | 6 | 6 | Workflow, ingest.py, dependabot |
| 2. Python Pipeline | 6 | 15 | All pipeline .py files, config |
| 3. Web Frontend | 6 | 12 | All web HTML/CSS/JS files |
| 4. Testing & Observability | 4 | 7 | Tests, workflow |
| **Total** | **22** | **40** | **Full codebase** |

## Execution Order

1. Section 1 first (unblocks reliable CI/CD for all subsequent changes)
2. Section 2 next (clean data layer before touching presentation)
3. Section 3 (frontend improvements with stable backend)
4. Section 4 last (tests validate all prior changes)
