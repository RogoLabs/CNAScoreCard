# CNA Scorecard Pipeline Directory Cleanup

## Essential Files (KEEP)
- `run_pipeline.py` — Main entry point, orchestrates the full pipeline
- `scoring.py` — CVE scoring logic (pure, canonical)
- `aggregation.py` — CNA aggregation and trend logic (new schema)
- `trend.py` — Canonical month-by-month trend calculation
- `output.py` — Handles writing JSON outputs
- `completeness.py` — Field utilization and completeness stats
- `ingest.py` — Data loading utilities
- `sync_cna_list.py` — Syncs CNA list from official source

## Legacy/Obsolete/Redundant Files (REMOVE)
- `cna_scorecards.py` — Legacy aggregation/scoring logic (replaced by aggregation.py)
- `debug_pipeline.py` — Old debug/experimental pipeline logic
- `fix_recent_cves.py` — Temporary script for recent CVE fix (now in main pipeline)
- `generate_individual_cna_jsons.py` — Legacy JSON output (replaced by new schema logic)

## Actions
- Remove all files in the REMOVE section above.
- Confirm that all pipeline runs and outputs work as expected after cleanup.
- Document any additional removals or changes here for future maintainers.
