# CNA Scorecard End-of-Year Roadmap 2025

## Executive Summary

This roadmap outlines improvements to the CNA Scorecard pipeline and web interface focusing on four key areas: **Schema Compatibility**, **Speed**, **Code Quality**, and **Usability**. 

> ⚠️ **Important:** The scoring rubric has been reviewed and approved by government, CNA, and community stakeholders. This roadmap **does not** propose any changes to scoring criteria.

---

## 🎯 Priority 1: CVE Schema Compatibility (Critical)

### Current State
- Pipeline currently uses **CVE Schema 5.1** (`dataVersion: "5.1"`)
- Latest official schema is **CVE Schema 5.2** (default in schema docs)

### Required Changes

#### 1.1 Update Schema Version Tracking
**File:** [cnascorecard_pipeline/config.py](cnascorecard_pipeline/config.py)

```python
# Add schema version configuration
CVE_SCHEMA_VERSION = "5.2"
SUPPORTED_SCHEMA_VERSIONS = ["5.0", "5.1", "5.2"]
```

#### 1.2 Ensure Schema 5.2 Compatibility
**File:** [cnascorecard_pipeline/scoring.py](cnascorecard_pipeline/scoring.py)

> ⚠️ **Note:** The scoring rubric has been reviewed and approved by government, CNA, and community stakeholders. No changes to scoring criteria without formal review process.

**Goal:** Ensure the pipeline gracefully handles CVE 5.2 records without breaking, while maintaining the existing approved scoring rubric.

| CVE 5.2 Field | Compatibility Status | Notes |
|---------------|---------------------|-------|
| `cpeApplicability` | ✅ Already handled | Used in Software Identification scoring |
| `taxonomyMappings` | ✅ No action needed | Not in scoring rubric |
| `tags` (cnaTags/adpTags) | ✅ No action needed | Not in scoring rubric |
| `configurations` | ✅ No action needed | Not in scoring rubric |
| `workarounds` | ✅ No action needed | Not in scoring rubric |
| `solutions` | ✅ No action needed | Not in scoring rubric |
| `exploits` | ✅ No action needed | Not in scoring rubric |
| `timeline` | ✅ No action needed | Not in scoring rubric |
| `credits` | ✅ No action needed | Not in scoring rubric |

**Action Required:** Test pipeline against CVE 5.2 records to verify no parsing errors or unexpected behavior with new fields.

---

## 🚀 Priority 2: Speed Improvements

### 2.1 Pipeline Performance

#### 2.1.1 Parallel CVE Processing
**Current:** Sequential file loading and scoring  
**Proposed:** Multiprocessing for CVE file loading

```python
# cnascorecard_pipeline/ingest.py
from concurrent.futures import ProcessPoolExecutor
import multiprocessing

def load_cve_records_parallel(cve_dir, start_date, end_date, workers=None):
    """Load CVE records using parallel processing."""
    if workers is None:
        workers = min(multiprocessing.cpu_count(), 8)
    
    cve_files = _get_cve_file_list(cve_dir, start_date, end_date)
    
    with ProcessPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(_load_single_cve_file, cve_files))
    
    return [r for r in results if r is not None]
```

**Estimated Impact:** 3-5x faster loading for ~300k CVE files

#### 2.1.2 Incremental Processing
**Current:** Full dataset reload every 6 hours  
**Proposed:** Delta-based processing using `delta.json`

```python
# cnascorecard_pipeline/ingest.py
def load_delta_cves(delta_file: Path) -> List[Dict]:
    """Load only changed CVEs since last run."""
    delta = load_json_file(delta_file)
    return [
        load_single_cve_file(cve['cveId']) 
        for cve in delta.get('new', []) + delta.get('updated', [])
    ]
```

**Estimated Impact:** 90% reduction in processing time for regular runs

#### 2.1.3 Caching Layer
**Proposed:** Add caching for computed scores

```python
# cnascorecard_pipeline/cache.py
import hashlib
import json
from pathlib import Path

class ScoreCache:
    """Cache for computed CVE scores."""
    
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        
    def get_score(self, cve_id: str, cve_hash: str) -> Optional[Dict]:
        """Retrieve cached score if CVE hasn't changed."""
        cache_file = self.cache_dir / f"{cve_id}.json"
        if cache_file.exists():
            cached = load_json_file(cache_file)
            if cached.get('hash') == cve_hash:
                return cached['score']
        return None
```

### 2.2 Web Performance (Static Site Compatible)

#### 2.2.1 Data Chunking for Lazy Loading
**Current:** All CNA data loaded upfront in single JSON file  
**Proposed:** Pre-split data into chunks during pipeline build

```python
# cnascorecard_pipeline/pipeline.py - generate chunked output
def write_chunked_cna_data(cna_list: list, chunk_size: int = 50):
    """Split CNA data into static chunks for lazy loading."""
    for i in range(0, len(cna_list), chunk_size):
        chunk = cna_list[i:i + chunk_size]
        chunk_file = f"cna_chunk_{i // chunk_size}.json"
        write_json(chunk, f"web/data/chunks/{chunk_file}")
    
    # Write manifest for client-side loader
    manifest = {
        "totalCNAs": len(cna_list),
        "chunkSize": chunk_size,
        "totalChunks": (len(cna_list) + chunk_size - 1) // chunk_size
    }
    write_json(manifest, "web/data/chunks/manifest.json")
```

```javascript
// web/cna/cna-index.js - client-side lazy loading from static chunks
let manifest = null;
const loadedChunks = new Map();

async function loadChunk(chunkIndex) {
    if (loadedChunks.has(chunkIndex)) return loadedChunks.get(chunkIndex);
    const response = await fetch(`data/chunks/cna_chunk_${chunkIndex}.json`);
    const chunk = await response.json();
    loadedChunks.set(chunkIndex, chunk);
    return chunk;
}

async function loadCNAPage(page, pageSize = 50) {
    if (!manifest) {
        manifest = await fetch('data/chunks/manifest.json').then(r => r.json());
    }
    const chunkIndex = Math.floor((page * pageSize) / manifest.chunkSize);
    return loadChunk(chunkIndex);
}
```

#### 2.2.2 Search Index Pre-computation
**Proposed:** Generate search index during pipeline run

```javascript
// web/data/search_index.json
{
  "cnas": ["Microsoft", "Google", ...],
  "products": {"Microsoft": ["Windows", "Office"], ...},
  "cweIds": ["CWE-79", "CWE-89", ...]
}
```

#### 2.2.3 Asset Optimization
- Minify CSS/JS files
- Add service worker for offline capability
- Implement asset caching headers

---

## 📊 Priority 3: Quality Improvements

> ⚠️ **Note:** The scoring rubric is stakeholder-approved. Quality improvements in this section focus on **code quality and testing**, not changes to how scores are calculated.

### 3.1 Test Coverage Expansion

#### 3.1.1 Add Schema Validation Tests
```python
# cnascorecard_pipeline/tests/test_schema.py
import jsonschema

def test_output_matches_expected_schema():
    """Ensure pipeline output matches documented schema."""
    pass

def test_cve_parsing_all_versions():
    """Test parsing CVEs from 5.0, 5.1, and 5.2 schemas."""
    pass
```

#### 3.1.2 Add Integration Tests
```python
# cnascorecard_pipeline/tests/test_integration.py
def test_full_pipeline_execution():
    """Test complete pipeline from ingest to output."""
    pass

def test_incremental_update():
    """Test delta-based updates work correctly."""
    pass
```

### 3.2 CI/CD Improvements

#### 3.2.1 GitHub Actions Enhancements
**Current:** Basic pipeline run every 6 hours  
**Proposed:** Enhanced workflow with:

```yaml
# .github/workflows/run-pipeline.yml improvements
- name: Cache pip dependencies
  uses: actions/cache@v4
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}

- name: Cache CVE data (shallow clone optimization)
  uses: actions/cache@v4
  with:
    path: cve_data
    key: cve-data-${{ github.run_number }}
    restore-keys: cve-data-
```

#### 3.2.2 Pipeline Monitoring
**Proposed:** Add failure notifications and metrics

- Slack/email notifications on pipeline failures
- Track pipeline runtime metrics over time
- Alert if data freshness exceeds threshold (>12 hours)

#### 3.2.3 Dependency Security
**Proposed:** Add automated security scanning

```yaml
# .github/workflows/security.yml
- name: Check for security vulnerabilities
  run: |
    pip install safety
    safety check -r requirements.txt
```

### 3.3 Code Quality Improvements

#### 3.3.1 Type Hints
**Current:** Partial type hints  
**Proposed:** Full type coverage with mypy strict mode

```python
# Example: cnascorecard_pipeline/scoring.py
def score_cve_record(cve: Dict[str, Any], config: ScoringConfig) -> CVEScore:
    """Score a CVE record and return structured result."""
    ...
```

#### 3.3.2 Error Handling
**Current:** Basic try/except  
**Proposed:** Graceful degradation for malformed CVEs

```python
# cnascorecard_pipeline/ingest.py
def load_cve_safe(filepath: Path) -> Optional[Dict]:
    """Load CVE with comprehensive error handling."""
    try:
        data = load_json_file(filepath)
        validate_cve_structure(data)
        return data
    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON in {filepath}: {e}")
        return None
    except ValidationError as e:
        logger.warning(f"Invalid CVE structure in {filepath}: {e}")
        return None
```

---

## 🎨 Priority 4: Usability Improvements

### 4.1 Web Interface Enhancements

#### 4.1.1 Enhanced CNA Detail Pages
**Current:** Basic scoring breakdown  
**Proposed:** Rich detail pages with:
- Historical trend charts
- Top CVEs by score
- Field utilization heatmaps
- Comparison with ecosystem averages

#### 4.1.2 CVE Search Functionality
**Proposed:** Add CVE search to find specific vulnerabilities

```html
<!-- web/index.html -->
<div class="search-container">
    <input type="text" id="cve-search" placeholder="Search CVE-XXXX-XXXXX...">
    <button onclick="searchCVE()">Search</button>
</div>
```

#### 4.1.3 Export Capabilities
**Proposed:** Add data export options

- CSV export for CNA rankings
- JSON export for raw data
- PDF report generation for individual CNAs

#### 4.1.4 Responsive Mobile Design
**Current:** Basic responsive  
**Proposed:** Enhanced mobile experience

- Collapsible tables for narrow screens
- Touch-friendly filtering
- Swipe navigation between CNAs

### 4.2 Mobile-First Redesign

#### 4.2.1 Mobile Layout Strategy
**Goal:** Full-featured mobile experience for security analysts on the go

**Breakpoints:**
| Breakpoint | Target | Layout |
|------------|--------|--------|
| < 480px | Phone portrait | Single column, stacked cards |
| 480-768px | Phone landscape / Small tablet | Two column grid |
| 768-1024px | Tablet | Sidebar + content |
| > 1024px | Desktop | Full layout |

**CSS Implementation:**
```css
/* web/assets/mobile.css */
/* Mobile-first base styles */
.cna-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
}

/* Tablet */
@media (min-width: 768px) {
    .cna-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

/* Desktop */
@media (min-width: 1024px) {
    .cna-grid {
        grid-template-columns: repeat(3, 1fr);
    }
}
```

#### 4.2.2 Mobile Navigation
**Current:** Desktop-oriented top navigation  
**Proposed:** Mobile-friendly navigation patterns

- **Bottom navigation bar** for primary actions (Home, CNAs, Trends, Search)
- **Hamburger menu** for secondary pages (Scoring, Completeness, About)
- **Sticky headers** that collapse on scroll
- **Pull-to-refresh** gesture support

```html
<!-- Mobile bottom navigation -->
<nav class="mobile-nav">
    <a href="/" class="nav-item active">
        <svg class="nav-icon"><!-- home icon --></svg>
        <span>Home</span>
    </a>
    <a href="/cna/" class="nav-item">
        <svg class="nav-icon"><!-- list icon --></svg>
        <span>CNAs</span>
    </a>
    <a href="/trends.html" class="nav-item">
        <svg class="nav-icon"><!-- chart icon --></svg>
        <span>Trends</span>
    </a>
    <a href="#search" class="nav-item">
        <svg class="nav-icon"><!-- search icon --></svg>
        <span>Search</span>
    </a>
</nav>
```

#### 4.2.3 Mobile-Optimized Data Tables
**Challenge:** CNA leaderboard tables don't fit on mobile screens  
**Solution:** Card-based layout with expandable details

```html
<!-- Mobile CNA card (replaces table row) -->
<div class="cna-card">
    <div class="cna-card-header">
        <span class="cna-rank">#1</span>
        <span class="cna-name">Microsoft</span>
        <span class="cna-grade grade-a">A</span>
    </div>
    <div class="cna-card-summary">
        <span class="score">92.5</span>
        <span class="cve-count">1,234 CVEs</span>
    </div>
    <button class="expand-btn" aria-expanded="false">
        View Details
    </button>
    <div class="cna-card-details" hidden>
        <!-- Expanded scoring breakdown -->
    </div>
</div>
```

#### 4.2.4 Touch-Friendly Interactions
**Proposed enhancements:**

- **Larger tap targets** (minimum 44x44px per WCAG)
- **Swipe gestures:**
  - Swipe left/right between CNA detail pages
  - Swipe down to refresh data
  - Swipe up to dismiss modals
- **Long-press actions:**
  - Long-press CNA to quick-view score breakdown
  - Long-press grade badge to copy embed code
- **Pinch-to-zoom** on trend charts

```javascript
// web/shared/touch-gestures.js
class SwipeHandler {
    constructor(element, options = {}) {
        this.element = element;
        this.threshold = options.threshold || 50;
        this.onSwipeLeft = options.onSwipeLeft || (() => {});
        this.onSwipeRight = options.onSwipeRight || (() => {});
        this.init();
    }
    
    init() {
        let startX = 0;
        this.element.addEventListener('touchstart', (e) => {
            startX = e.touches[0].clientX;
        });
        this.element.addEventListener('touchend', (e) => {
            const endX = e.changedTouches[0].clientX;
            const diff = endX - startX;
            if (Math.abs(diff) > this.threshold) {
                diff > 0 ? this.onSwipeRight() : this.onSwipeLeft();
            }
        });
    }
}
```

#### 4.2.5 Mobile Performance Optimization
**Goal:** Sub-2-second load time on 3G connections

- **Critical CSS inlining** for above-the-fold content
- **Lazy load** charts and non-visible CNA data
- **Image optimization:**
  - SVG badges (already implemented)
  - WebP format for any raster images
  - Responsive image srcsets
- **Service worker** for offline capability
- **Data prefetching** for likely next pages

```javascript
// Intersection Observer for lazy loading
const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            loadCNAData(entry.target.dataset.cna);
            observer.unobserve(entry.target);
        }
    });
}, { rootMargin: '100px' });

document.querySelectorAll('.cna-card[data-cna]').forEach(card => {
    observer.observe(card);
});
```

#### 4.2.6 Progressive Web App (PWA)
**Proposed:** Convert to installable PWA

- **Web App Manifest** for home screen installation
- **Service Worker** for offline access to cached data
- **Push notifications** for CNA score changes (optional)

```json
// web/manifest.json
{
    "name": "CNA Scorecard",
    "short_name": "Scorecard",
    "description": "Track CVE data quality across CNAs",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#1a1a2e",
    "theme_color": "#4a9eff",
    "icons": [
        {
            "src": "/assets/icon-192.png",
            "sizes": "192x192",
            "type": "image/png"
        },
        {
            "src": "/assets/icon-512.png",
            "sizes": "512x512",
            "type": "image/png"
        }
    ]
}
```

### 4.3 Documentation Improvements

#### 4.2.1 Data Structure Documentation
**Proposed:** Document JSON data file structures for developers/integrators

```markdown
# web/data/README.md
## Data File Reference

### cna_summary.json
Array of CNA summary objects...

### cna_combined.json
Complete CNA data including individual CVE scores...
```

#### 4.2.2 Scoring Methodology Deep Dive
**Proposed:** Expand scoring.html with:
- Examples of high vs low scoring CVEs
- Interactive score calculator
- FAQ section

### 4.3 Accessibility Improvements

#### 4.3.1 WCAG 2.1 Compliance
- Add ARIA labels to interactive elements
- Ensure color contrast meets AA standards
- Add keyboard navigation support
- Screen reader optimization

#### 4.3.2 Internationalization Prep
- Extract text strings for potential translation
- Support RTL layouts
- Date/number formatting by locale

---

## 📅 Implementation Timeline

### Phase 1: Schema Compatibility (Week 1)
- [ ] Test pipeline against CVE 5.2 records
- [ ] Verify no parsing errors with new fields
- [ ] Update dataVersion tracking to support 5.2
- [ ] Add regression tests for schema compatibility

### Phase 2: Speed Optimization (Week 2-3)
- [ ] Implement parallel CVE loading
- [ ] Add delta processing support
- [ ] Implement score caching
- [ ] Optimize web asset loading

### Phase 3: Code Quality (Week 3-4)
- [ ] Add type hints throughout codebase
- [ ] Standardize logging and error handling
- [ ] Expand test coverage to 80%+
- [ ] Add pre-commit hooks for code quality

### Phase 4: Usability (Week 4-5)
- [ ] Enhance CNA detail pages
- [ ] Add search functionality
- [ ] Implement export features
- [ ] Improve mobile experience

### Phase 5: Mobile-First Redesign (Week 5-6)
- [ ] Implement mobile CSS breakpoints and card layouts
- [ ] Add bottom navigation bar for mobile
- [ ] Convert data tables to expandable cards
- [ ] Add touch gestures (swipe, long-press)
- [ ] Optimize performance for 3G connections
- [ ] Create PWA manifest and service worker
- [ ] Test on iOS Safari, Chrome Android, Firefox Mobile

### Phase 6: Documentation & Polish (Week 6-7)
- [ ] Complete data structure documentation
- [ ] Update README and guides
- [ ] Accessibility audit and fixes
- [ ] Performance testing and optimization

---

## 📋 Schema Field Coverage Matrix

> ⚠️ **Reminder:** Scoring Impact column reflects the current approved rubric. No changes without stakeholder review.

| CVE 5.2 Field | Current Status | Scoring Impact | Completeness Tracking |
|---------------|----------------|----------------|----------------------|
| `dataType` | ✅ Tracked | None | ✅ Yes |
| `dataVersion` | ✅ Tracked | None | ✅ Yes |
| `cveMetadata.*` | ✅ Tracked | None | ✅ Yes |
| `containers.cna.descriptions` | ✅ Scored | Foundational | ✅ Yes |
| `containers.cna.affected` | ✅ Scored | Foundational | ✅ Yes |
| `containers.cna.references` | ✅ Scored | Foundational + Patch | ✅ Yes |
| `containers.cna.problemTypes` | ✅ Scored | Root Cause | ✅ Yes |
| `containers.cna.metrics` | ✅ Scored | Severity | ✅ Yes |
| `containers.cna.cpeApplicability` | ✅ Scored | Software ID | ✅ Yes |
| `containers.cna.title` | ❌ Not Scored | None | ✅ Yes |
| `containers.cna.impacts` | ❌ Not Scored | None | ✅ Yes |
| `containers.cna.configurations` | ❌ Not Scored | None | ✅ Yes |
| `containers.cna.workarounds` | ❌ Not Scored | None | ✅ Yes |
| `containers.cna.solutions` | ❌ Not Scored | None | ✅ Yes |
| `containers.cna.exploits` | ❌ Not Scored | None | ✅ Yes |
| `containers.cna.timeline` | ❌ Not Scored | None | ✅ Yes |
| `containers.cna.credits` | ❌ Not Scored | None | ✅ Yes |
| `containers.cna.source` | ❌ Not Scored | None | ✅ Yes |
| `containers.cna.tags` | ❌ Not Tracked | None | ❌ Not tracked |
| `containers.cna.taxonomyMappings` | ❌ Not Tracked | None | ❌ Not tracked |
| `containers.adp` | ❌ Not Analyzed | None | ✅ Yes |

---

## 🔧 Technical Debt Items

### High Priority
1. **Remove hardcoded paths** - Use config throughout
2. **Add type hints** - Improve code maintainability
3. **Standardize logging** - Consistent log levels and formats
4. **Add error handling** - Graceful degradation for malformed CVEs

### Medium Priority
1. **Refactor aggregation.py** - Break into smaller functions
2. **Add docstrings** - Document all public functions
3. **Create data models** - Use dataclasses/Pydantic for CVE records
4. **Add configuration validation** - Validate rules.json on startup
5. **Add pip dependency caching** - Speed up GitHub Actions runs

### Low Priority
1. **Add code formatting** - Implement black/isort (already in requirements.txt)
2. **Add pre-commit hooks** - Automated code quality checks
3. **Create contributing guide** - For open source contributors
4. **Archive old CVE data** - Consider pruning data older than analysis window

---

## 📈 Success Metrics

| Metric | Current | Target | Measurement |
|--------|---------|--------|-------------|
| Pipeline runtime | ~10 min | < 3 min | Time to process 6 months of CVEs |
| Web page load (desktop) | ~2s | < 500ms | Lighthouse performance score |
| Web page load (mobile 3G) | Unknown | < 2s | Lighthouse throttled test |
| Mobile usability | Unknown | 100/100 | Lighthouse mobile score |
| Test coverage | ~40% | > 80% | pytest-cov report |
| Schema compliance | 5.1 | 5.2 | dataVersion support |
| Accessibility | Unknown | WCAG 2.1 AA | Lighthouse accessibility score |
| Pipeline reliability | Unknown | 99%+ | Successful runs / Total runs |
| PWA installability | ❌ No | ✅ Yes | Lighthouse PWA audit |

---

## 🚨 Risk Considerations

1. **Schema Backward Compatibility**: Ensure 5.0/5.1 CVEs still parse correctly
2. **Data Volume Growth**: CVE count growing ~30% YoY - need scalable solution
3. **Upstream Schema Changes**: CVE Project may update schema without notice
4. **Performance Trade-offs**: Parallel processing increases memory usage
5. **GitHub Pages Limits**: Monitor for bandwidth/storage constraints

---

## 📚 References

- [CVE Schema 5.2 Documentation](https://github.com/CVEProject/cve-schema/blob/main/schema/docs/CVE_Record_Format_bundled.json)
- [CNA Rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules)
- [CPE Specification](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe)
- [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)

---

*Last Updated: December 26, 2025*
*Document Version: 1.0*
