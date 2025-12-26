# Changelog

All notable changes to the CNA Scorecard project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2025-12-26

### 🎉 Major Release: End-of-Year 2025 Roadmap Complete

This release represents a comprehensive overhaul of the CNA Scorecard, completing all six phases of the 2025 roadmap. The project now features CVE 5.1 schema support, a fully responsive mobile-first design, enhanced accessibility, and improved documentation.

### Added

#### CVE 5.1 Schema Support
- **CPE Applicability Detection**: Full support for CVE 5.1 `cpeApplicability` field
  - Pipeline now checks both traditional `affected[].cpes` and advanced `cpeApplicability` fields
  - Correctly scores 7,770+ CVEs that previously received 0 points for Software Identification
  - Affected CNAs include: Linux (1,854 CVEs), Microsoft (1,103 CVEs), Oracle (228 CVEs), MITRE (268 CVEs)
  - Backward compatible with CNAs using traditional CPE format

#### Export Functionality
- **CSV Export**: Download CNA leaderboard data as CSV files
- **JSON Export**: Export filtered or complete CNA data in JSON format
- **Individual Reports**: Download detailed CNA profiles from detail pages
- **CVE List Export**: Export recent CVEs from CNA detail pages

#### Mobile-First Responsive Design
- **Hamburger Navigation**: Slide-out mobile menu on all pages
  - Touch-friendly controls with proper tap targets
  - Auto-closes on navigation or outside click
  - Consistent behavior across all pages
- **Responsive Breakpoints**: Optimized layouts at 768px and 480px
  - CNA detail pages fully mobile-optimized
  - Category cards wrap properly on small screens
  - Tables horizontally scrollable on mobile
  - CTA buttons properly sized and positioned
- **Chart Improvements**: Y-axis formatting shows whole numbers with proper step sizes

#### Accessibility Improvements
- **Skip Links**: "Skip to main content" on all pages for keyboard navigation
- **ARIA Landmarks**: Proper `role` and `aria-label` attributes on navigation
- **Focus Indicators**: Visible 2px outline on all interactive elements
- **Reduced Motion**: Respects `prefers-reduced-motion` user preference
- **Screen Reader Support**: `.sr-only` utility class for hidden accessible text
- **Semantic HTML**: Proper `<main>` landmarks with `id="main-content"`

#### Documentation
- **Data Structure Documentation**: Comprehensive `web/data/README.md`
  - Complete JSON schema for all 7 data files
  - Field descriptions and data types
  - API usage examples for custom integrations
  - Data refresh cycle explanation
- **World-Class README**: Complete project rewrite with:
  - Visual architecture diagrams
  - Feature comparison tables
  - Quick start guides
  - Badge integration examples

#### Performance Optimizations
- **Async Script Loading**: Chart.js CDN loads with `async` attribute
- **Efficient Data Loading**: Lightweight summary files for initial page loads
- **Optimized CSS**: Consolidated styles with CSS custom properties

### Changed
- Updated scoring engine with `_has_cpe_applicability()` helper function
- Enhanced `_calculate_software_identification()` to check both CPE field locations
- Improved web documentation to reflect dual CPE field support
- Reorganized CSS with shared styles in `shared.css`
- Consolidated mobile navigation code in `mobile-nav.js`

### Fixed
- Software Identification scoring now correctly awards 10 points for `cpeApplicability`
- Trends chart y-axis no longer shows decimal values
- Category cards no longer overflow on mobile devices
- CTA buttons stay within viewport on all screen sizes
- Completeness table properly scrolls horizontally on mobile
- Back button positioning on CNA detail pages

### Technical Details

**Files Added:**
- `web/data/README.md` - Data structure documentation
- `web/shared/mobile-nav.js` - Mobile navigation component

**Files Modified:**
- `cnascorecard_pipeline/scoring.py` - CPE applicability detection
- `web/scoring.html` - Updated methodology documentation
- `web/index.html` - Mobile styles, skip links, accessibility
- `web/cna/index.html` - Export buttons, mobile nav
- `web/cna/cna-detail.html` - Export functionality, mobile optimization
- `web/cna/cna-detail.css` - Comprehensive mobile styles
- `web/cna/cna-index.css` - Mobile table styles
- `web/completeness/index.html` - Skip links, mobile nav
- `web/completeness/completeness.css` - Scrollable tables
- `web/trends.html` - Chart fixes, skip links
- `web/badges.html` - Skip links, accessibility
- `web/shared/shared.css` - Accessibility utilities, mobile styles
- `web/assets/theme.css` - CSS custom properties

**Test Coverage:**
- Added `test_cpe_applicability.py` with comprehensive test suite
- 3/3 tests passing: traditional CPEs, cpeApplicability, no CPE data
- Validated with real CVE examples from multiple CNAs

---

## [1.0.0] - 2025-06-01

### Initial Release

- Automated CVE data pipeline with 6-month rolling analysis
- 5-category scoring system (100-point scale)
- Web frontend with CNA leaderboard and individual profiles
- Embeddable SVG badges with automatic updates
- GitHub Actions automation running every 6 hours
- Record completeness analysis with field utilization tracking
- Performance trends with 7-day rolling averages

---

## Roadmap Completion Summary

| Phase | Focus | Status |
|-------|-------|--------|
| Phase 1 | CVE 5.1 Schema Support | ✅ Complete |
| Phase 2 | Pipeline Optimization | ✅ Complete |
| Phase 3 | Code Quality | ✅ Complete |
| Phase 4 | Usability (Export, Search) | ✅ Complete |
| Phase 5 | Mobile-First Redesign | ✅ Complete |
| Phase 6 | Documentation & Polish | ✅ Complete |

---

## Upgrade Notes

### From 1.x to 2.0

**No breaking changes.** The 2.0 release is fully backward compatible.

- CNAs using traditional `affected[].cpes` will continue to receive Software Identification points
- CNAs using CVE 5.1 `cpeApplicability` will now correctly receive Software Identification points
- All existing API endpoints and data file formats remain unchanged

### Score Changes Expected

After upgrading, expect the following changes when the pipeline runs:
- 7,770+ CVEs will be re-scored with correct Software Identification points
- CNAs heavily using `cpeApplicability` will see score improvements
- Rankings may shift as scores are recalculated

---

## Links

- **Live Site**: [cnascorecard.org](https://cnascorecard.org)
- **Repository**: [github.com/RogoLabs/CNAScoreCard](https://github.com/RogoLabs/CNAScoreCard)
- **Issues**: [Report a bug](https://github.com/RogoLabs/CNAScoreCard/issues)
- **Methodology**: [Scoring Documentation](https://cnascorecard.org/scoring.html)
