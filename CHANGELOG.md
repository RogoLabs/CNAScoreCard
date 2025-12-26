# Changelog

All notable changes to the CNA Scorecard project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Added

#### Phase 4: Usability Improvements
- **CSV/JSON Export**: Added export functionality to CNA leaderboard and detail pages
  - Export all CNA data or filtered results
  - Download individual CNA reports in JSON format
  - Export recent CVE lists from detail pages

#### Phase 5: Mobile-First Redesign
- **Mobile Navigation**: Hamburger menu with slide-out navigation for all pages
  - Touch-friendly controls and tap targets
  - Auto-closes on navigation or outside click
  - Consistent across all web pages
- **Responsive Layouts**: Comprehensive mobile breakpoints at 768px and 480px
  - CNA detail page optimized for mobile viewing
  - Category cards wrap properly on small screens
  - Tables horizontally scrollable on mobile
  - CTA buttons properly sized for mobile
- **Chart Improvements**: Fixed y-axis formatting to show whole numbers

#### Phase 6: Documentation & Polish
- **Data Structure Documentation**: Comprehensive README for `web/data/` directory
  - Complete JSON schema documentation for all data files
  - API usage examples for custom integrations
  - Data refresh cycle explanation

#### CVE 5.1 Schema Support
- **CPE Applicability Detection**: Added support for CVE 5.1 `cpeApplicability` field for Software Identification scoring
  - Pipeline now checks both traditional `affected[].cpes` and advanced `cpeApplicability` fields
  - Fixes scoring for 7,770+ CVEs that use the CVE 5.1 advanced CPE format
  - Major CNAs affected: Linux (1,854 CVEs), Microsoft (1,103 CVEs), Oracle (228 CVEs), MITRE (268 CVEs), Lenovo (31 CVEs)
  - Backward compatible - no breaking changes for CNAs using traditional `cpes` field
  
### Fixed
- Software Identification scoring now correctly awards 10 points for CVEs using `cpeApplicability`
- Resolved bug reported by IBM PSIRT where CVE 5.1 CPE data was not being detected

### Changed
- Updated `scoring.py` with new `_has_cpe_applicability()` helper function
- Enhanced `_calculate_software_identification()` to check both CPE field locations
- Updated web documentation (`scoring.html`) to reflect dual CPE field support
- Updated `README.md` to highlight CVE 5.1 schema support

### Technical Details
- **Files Modified**:
  - `/cnascorecard_pipeline/scoring.py` - Core CPE detection logic
  - `/web/scoring.html` - Technical documentation
  - `/README.md` - Feature documentation
  
- **Test Coverage**:
  - Added comprehensive test suite in `test_cpe_applicability.py`
  - 3/3 tests passing: traditional CPEs, cpeApplicability, and no CPE data scenarios
  - Validated with real CVE examples: CVE-2025-2502 (Lenovo), CVE-2025-0163 (IBM)

### Impact
When the next pipeline runs:
- 7,770+ CVEs will be re-scored with correct Software Identification points (0 → 10)
- Major CNA score improvements expected across the ecosystem
- More accurate CNA rankings reflecting actual data quality
- IBM PSIRT and other CNAs can use advanced CVE 5.1 features without scoring penalties

---

## Release Notes Template

For future releases, use this template:

```markdown
## [Version] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Features marked for removal

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security updates
```
