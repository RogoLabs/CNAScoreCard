# Plan: Count Package URLs in Software Identification

Issue: [RogoLabs/CNAScoreCard#38](https://github.com/RogoLabs/CNAScoreCard/issues/38), "Incorporate Package URLs when scoring software identifier usage" (opened 2026-10-21 by Andrew Lilley Brinker).

## Background

CVE JSON schema 5.2 (released 2025-10-29) added `containers.cna.affected[].packageURL`: a single string per affected product, described as "a Package URL ... The Package URL MUST NOT include a version." Today the Software Identification category (10 points) only checks `affected[].cpes` and `cpeApplicability`, so a record that identifies its software with a PURL and no CPE scores 0 in that category.

5.2 is now the dominant format: 106,067 of 122,409 non-rejected 2025/2026 records use `dataVersion: 5.2`.

## Impact analysis

Measured against the repo's local `cve_data` checkout, refreshed to cvelistV5 `eec446ce44` (2026-10-24 23:45 UTC), using the pipeline's own window (`datePublished` within the last 6 months, 2026-04-24 through 2026-10-24): 66,548 published, non-rejected records.

| Metric | Records | Share |
|---|---|---|
| Has CPE (either field) | 27,899 | 41.9% |
| Has PURL | 5,000 | 7.5% |
| Has both | 3,078 | 4.6% |
| **PURL only (would gain 10 points)** | **1,922** | **2.9%** |

One of those 1,922 is the malformed apache PURL below, so the implemented rule awards points to 1,921 records.

Software Identification coverage across the window would go from 41.9% to 44.8%.

CNAs whose average score would rise (average gain = PURL-only share x 10 points):

| CNA | PURL-only / records in window | Avg score gain |
|---|---|---|
| openjs | 118 / 119 | +9.9 |
| bcorg | 51 / 74 | +6.9 |
| CPANSec | 117 / 298 | +3.9 |
| apache | 321 / 1,095 | +2.9 |
| VulnCheck | 1,289 / 6,796 | +1.9 |
| Anthropic | 1 / 5 | +2.0 |
| seal | 1 / 7 | +1.4 |
| Nozomi | 1 / 58 | +0.2 |
| mitre | 22 / 2,380 | +0.1 |

No CNA's score goes down under the recommended approach.

Data quality observations:

- PURL types in use: github (1,971), npm (1,264), pypi (655), golang (439), maven (421), hex (263), composer (260), cargo (212), cpan (128), otp (61), software-id (55), nuget, generic, gem, opam.
- No PURLs in the window include a version. An earlier count of 30 was wrong: all 30 were scoped npm names such as `pkg:npm/@fastify/middie` (openjs), where the leading `@` is a scope, not a version.
- 1 PURL is malformed: `pkg:/maven/org.apache.wss4j/wss4j-ws-security-dom` (CVE-2026-92899), empty type.

## Decisions

1. **PURL is equivalent to CPE (recommended).** Either identifier satisfies the category; it stays binary at 10 points and no weights change. Alternatives considered and rejected:
   - Splitting the 10 points between CPE and PURL would cut scores for every CPE-only CNA (the large majority) to reward a format most closed-source vendors cannot use.
   - A bonus on top of CPE breaks the 100 point scale.
2. **Light validation.** Count a `packageURL` only when it is a string matching `^pkg:[A-Za-z][A-Za-z0-9.+-]*/.+` (scheme, non-empty type, something after the slash). This rejects the `pkg:/maven/...` case and empty strings. **Decided:** versioned PURLs do not count, following the schema's "MUST NOT include a version" rule. A version is an `@` after a name character, so scoped npm names (`pkg:npm/@fastify/static`) still count. No records in the current window are affected.
3. **No change to CPE checks.** They remain presence checks; tightening them is out of scope.

## Implementation steps

1. **Scoring** ([scoring.py](../../cnascorecard_pipeline/scoring.py))
   - Add a pre-compiled `_PURL_PATTERN` next to `_CWE_PATTERN`.
   - Add `_has_package_urls(affected)`, mirroring `_has_cpe_identifiers`: returns True if any affected product has a string `packageURL` matching the pattern.
   - Call it in `_calculate_software_identification` after the two CPE checks, with a matching debug log line.
   - Update the module docstring (line 30, "valid CPE in affected") and the function docstring to say "CPE or PURL".
2. **Rules** ([rules.json](../../cnascorecard_pipeline/rules.json)): change `softwareIdentification.criteria` to `["validCPE", "validPURL"]`.
3. **Completeness / field insights**
   - [config.py](../../cnascorecard_pipeline/config.py): add `'affected.packageURL': 'softwareIdentification'` to the category map and a `CANONICAL_FIELDS` entry ("Package URL (PURL) identifiers", importance High, category `softwareIdentification`).
   - [completeness.py](../../cnascorecard_pipeline/completeness.py): add `"affected.packageURL": {"path": [..., "affected"], "check": "has_package_url"}` and the `has_package_url` branch in `_custom_check`.
   - Confirm [completeness.js](../../web/completeness/completeness.js) renders a second field under the `softwareIdentification` category without layout changes.
4. **Score cache** ([cache.py](../../cnascorecard_pipeline/cache.py)): the cache key is a hash of the CVE JSON only, so a rules change leaves stale scores in a local `web/data/.cache/scores`. Fold a `SCORING_VERSION` constant into `compute_hash` and bump it with this change. (CI is unaffected today because that directory is gitignored and not in `actions/cache`, but this protects local runs and any future CI caching.)
5. **Tests**
   - [test_scoring.py](../../cnascorecard_pipeline/tests/test_scoring.py): PURL-only scores 10; PURL plus CPE scores 10; malformed `pkg:/maven/x` scores 0; empty string and non-string values score 0; versioned PURL scores 10; direct tests for `_has_package_urls`.
   - [test_completeness.py](../../cnascorecard_pipeline/tests/test_completeness.py): `has_package_url` true/false cases.
   - [test_cache.py](../../cnascorecard_pipeline/tests/test_cache.py): hash changes when `SCORING_VERSION` changes.
6. **Web copy**
   - [scoring.html](../../web/scoring.html): Software Identification description (around lines 185 to 210), the field list (around 465 to 510), and the embedded code sample (around 510 to 560).
   - [index.html:676](../../web/index.html:676): description "Common Platform Enumeration (CPE)" becomes "CPE or Package URL (PURL)".
   - [trends.html:293](../../web/trends.html:293): chart title "Software Identification (CPE)" becomes "Software Identification (CPE/PURL)".
7. **Docs**: [README.md:78](../../README.md:78), a CHANGELOG entry noting which CNAs gain and by how much, and the field tables in [roadmap.md](../../roadmap.md) (lines 37 and 607) adding `affected[].packageURL` as scored.

## Verification and rollout

1. Keep local `cve_data` current (`git fetch --depth=1 origin main && git reset --hard origin/main` inside it, as CI does); it was refreshed on 2026-10-24 for this analysis.
2. Run `python cnascorecard_pipeline/pipeline.py --no-cache` before and after the change and diff `web/data/cna_summary.json` for the CNAs in the table above. Expected: only those CNAs move, upward, by roughly the amounts listed.
3. Check that `performance_trends.json` is recomputed from records each run (as `trends.py` appears to do), so the trend line shifts as a whole rather than showing a step on release day.
4. Comment on issue #38 with the impact numbers and close it with the PR.
