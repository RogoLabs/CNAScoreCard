# Scoring Rubric Review: Package URLs in Software Identification

Change under review: [RogoLabs/CNAScoreCard#39](https://github.com/RogoLabs/CNAScoreCard/pull/39), closing [#38](https://github.com/RogoLabs/CNAScoreCard/issues/38).

[roadmap.md](../../roadmap.md) states that the scoring rubric was approved by government, CNA, and community stakeholders and that it does not change without formal review. This document is the review package for that sign-off: the exact rubric change, its measured impact, a technical review, and the decisions reviewers are asked to approve.

## 1. Rubric change

| | Before | After |
|---|---|---|
| Category | Software Identification | Software Identification (unchanged) |
| Weight | 10 points | 10 points (unchanged) |
| Scoring | Binary | Binary (unchanged) |
| Criteria (`rules.json`) | `validCPE` | `validCPE`, `validPURL` |
| Satisfied by | `affected[].cpes` or `cpeApplicability` | Either of those, **or** a valid `affected[].packageURL` |

A `packageURL` is valid when it:

- has the shape `pkg:type/name` (type starts with a letter, something follows the slash), and
- carries no version. The CVE schema says the Package URL "MUST NOT include a version." A version is an `@` after a name character, so `pkg:npm/lodash@4.17.21` is rejected and the scoped npm name `pkg:npm/@fastify/static` is accepted.

Only the CNA container is scored, the same as for CPE.

## 2. Measured impact

Scored with the pipeline's own `score_cve_record`, before and after the change, on cvelistV5 as of 2026-10-24 23:45 UTC. Window: `datePublished` from 2026-04-24 through 2026-10-24, 66,548 published, non-rejected records.

| | Records with Software ID points | Share |
|---|---|---|
| Before | 27,899 | 41.9% |
| After | 29,820 | 44.8% |
| Change | +1,921 | +2.9 pts |

**No record and no CNA loses points.**

| CNA | Records gaining points / records in window | Avg score gain |
|---|---|---|
| openjs | 118 / 119 | +9.9 |
| bcorg | 51 / 74 | +6.9 |
| CPANSec | 117 / 298 | +3.9 |
| apache | 321 / 1,095 | +2.9 |
| Anthropic | 1 / 5 | +2.0 |
| VulnCheck | 1,289 / 6,796 | +1.9 |
| seal | 1 / 7 | +1.4 |
| Nozomi | 1 / 58 | +0.2 |
| mitre | 22 / 2,380 | +0.1 |

Overall, 5,000 records (7.5%) carry a PURL. 3,078 of them already had a CPE, so the change only affects records whose only software identifier is a PURL.

## 3. Technical review

1. **No regressions.** Before/after scoring shows only increases, limited to the CNAs above. All 264 pipeline tests pass, including new cases for PURL only, PURL plus CPE, versioned, scoped npm, malformed, and non-string values.
2. **Schema alignment.** `affected[].packageURL` is defined in CVE JSON 5.2 (released 2025-10-29). 5.2 is now the majority format: 139,269 of 395,281 non-rejected records in cvelistV5, and most new records.
3. **Version rule.** Matches the schema. No records in the current window are rejected by it, so it guards against future misuse and doesn't take points from anyone today.
4. **Malformed values.** One PURL in the window is malformed (`pkg:/maven/org.apache.wss4j/wss4j-ws-security-dom`, CVE-2026-92899, apache, empty type) and correctly earns nothing.
5. **CNA container only.** PURLs added by ADPs don't count, consistent with CPE. No record in the window has a PURL only in an ADP container.
6. **Trend history.** `trends.py` recomputes daily trends and top improvers from scored records on every run. The whole history moves up at once, with no jump on the release date and no CNA wrongly listed as an "improver."
7. **Type is not checked against the registry.** The rule checks shape, not whether the type is in the [purl-spec type registry](https://github.com/package-url/purl-spec/tree/main/types). Every type in the window is registered except `software-id`, which 55 records use (EEF 38, apache 17; for example `pkg:software-id/apache.org/cocoon`, `pkg:software-id/erlang.org/otp`). For 17 apache records it is the only identifier, so they earn points only because unregistered types are accepted. (`pkg:generic/...` is a registered catch-all type; 20 such values appear, none as a record's only identifier.) See decision C.
8. **Stricter than CPE.** CPE is a presence check: any non-empty `affected[].cpes` list earns the points. PURL is checked for shape and version. For example, 1,047 records in the window have `affected[].cpes` entries but none in CPE 2.3 format (mostly Red Hat CPE 2.2 URIs such as `cpe:/o:redhat:enterprise_linux:10`, plus some malformed 2.3 strings), and they score today. This PR doesn't change CPE handling. The difference is noted so reviewers aren't surprised by it.
9. **Gaming risk.** A low-effort PURL such as `pkg:generic/product` earns the points. This matches the existing CPE risk, where a wildcard CPE earns the points too. Neither category measures accuracy, only presence.

### Alternatives considered

| Option | Why not recommended |
|---|---|
| Split the 10 points between CPE and PURL | Lowers scores for every CPE-only CNA (most CNAs, including closed-source vendors who have no PURL to give) |
| PURL as a bonus on top of CPE | Pushes the maximum past 100 points and breaks grade thresholds |
| Keep CPE only | Ignores an identifier the CVE Program now officially supports, and penalizes open source CNAs that use it |

## 4. Decisions for sign-off

| # | Decision | Recommendation |
|---|---|---|
| A | A valid PURL is equivalent to a CPE for the 10 Software Identification points | Approve |
| B | Versioned PURLs don't count, per the schema | Approve |
| C | PURLs with an unregistered type (for example `pkg:software-id/...`) count, as long as they're well formed | Approve for now; revisit if misuse appears. The alternative, requiring a registered type, would give 17 apache records 0 instead of 10 (apache's gain drops from 321 to 304 records, about +2.8 instead of +2.9) |
| D | Ship as a scoring change effective on merge, with history recomputed under the new rule | Approve |

## 5. Sign-off

| Stakeholder group | Reviewer | Decisions approved (A to D) | Date |
|---|---|---|---|
| Government | | | |
| CNA | | | |
| Community | | | |

Reproduction: the scripts used for the numbers above score `cve_data/cves` with `cnascorecard_pipeline/scoring.py` at the PR head and at `main`, over the window above.
