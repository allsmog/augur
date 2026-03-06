---
name: augur
description: >
  Run IRIS neurosymbolic SAST. Trigger on: run IRIS, run augur,
  neurosymbolic SAST, custom CodeQL taint analysis, LLM-labeled static
  analysis, find vulns with CodeQL, generate custom taint queries from
  LLM-labeled sources/sinks.
---

Read `/Users/Shayaun.Nejad/VibeCode/open-sourced/augur/WORKFLOW.md` and follow the two-phase pipeline exactly.

Example invocations:

- `Run augur on DB /path/to/codeql-db for all passes`
- `Run IRIS/augur on /path/to/codeql-db for pass 1 and pass 5`
- `Generate labels and stop at checkpoint for review`

Required input parameters:

1. `db_path`: absolute path to a CodeQL database
2. `passes`: optional subset of `1..13` (default all)
3. `model`: LLM identifier for labeling
4. `project_root`: optional source root for richer framework detection

Expected outputs:

- `iris/exploration/*` detection and run metadata
- `iris/extraction/*` candidate extraction artifacts
- `iris/labels/labels.json` (schema-valid)
- `iris/libraries/*.qll` generated source/sink/sanitizer/summary libraries
- `iris/queries/Pass*.ql` rendered pass queries
- `iris/results/pass*.sarif` sequential analysis outputs
- `iris/report/iris_report.md` filtered final report

Execution rules:

1. Run Step 0 pre-flight before any query execution.
2. Load reference files on-demand based on detected language/framework.
3. Run extraction and taint queries sequentially.
4. Present checkpoint summary. In interactive mode, pause for human review before Phase 2; in automated mode, log the summary and continue.
5. Use `scripts/filter_and_report.py` to produce final report.
