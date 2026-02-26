# Augur Workflow (Agent-Agnostic IRIS Pipeline)

This file is the execution contract for Augur.

Follow this pipeline exactly to reproduce the IRIS-style neuro-symbolic flow:

- Symbolic stage: extract APIs and run taint analysis with CodeQL
- Neural stage: label candidate APIs and contextualize alerts with an LLM
- Human stage: review labels before the heavy analysis run

The workflow is agent-agnostic. It assumes only:

1. File read/write access
2. Shell execution
3. LLM invocation

## 0. Pipeline shape

Augur uses two phases and eight stages (Step 0-6 + mandatory checkpoint):

- Phase 1: Extract and label
- Phase 2: Analyze and report

Stages:

1. Step 0: Pre-flight
2. Step 1: Explore and detect
3. Step 2: Extract source/sink candidates
4. Step 3: LLM label candidates
5. Checkpoint: Human review gate
6. Step 4: Generate CodeQL libraries
7. Step 5: Run taint queries
8. Step 6: Filter findings and write report

## 1. Inputs and outputs

### 1.1 Required input

- CodeQL database directory (for one target repo)
- Target CWE pass set (default: all six)
- LLM endpoint/model for labeling
- Project root path (optional, used for framework detection and heuristics)

### 1.2 Generated output tree

Create this tree at the workspace root:

```text
iris/
├── exploration/
├── extraction/
├── labels/
├── libraries/
├── queries/
├── results/
└── report/
```

Expected artifacts:

- `iris/exploration/detection.json`
- `iris/extraction/sources.ql`
- `iris/extraction/sinks.ql`
- `iris/extraction/sources.csv`
- `iris/extraction/sinks.csv`
- `iris/labels/labels.json`
- `iris/libraries/MySources.qll`
- `iris/libraries/MySinks.qll`
- `iris/libraries/MySanitizers.qll`
- `iris/libraries/MySummaries.qll`
- `iris/queries/Pass{1..6}_*.ql`
- `iris/results/pass{1..6}.sarif` or CSV equivalent
- `iris/report/iris_report.md`

## 2. CWE pass definitions

Use this exact mapping unless the user narrows scope.

| Pass | CWEs | Focus |
| --- | --- | --- |
| 1 | 022, 023, 036, 073 | Path Traversal |
| 2 | 077, 078, 088 | Command/Argument Injection |
| 3 | 918, 099, 610 | SSRF |
| 4 | 094, 095 | Code Injection |
| 5 | 089 | SQL Injection |
| 6 | 502 | Unsafe Deserialization |

## 3. Global operational rules (hard constraints)

These rules are mandatory:

1. Run `codeql pack install` before running any query.
2. Run all CodeQL query executions sequentially against the same DB.
3. Never run extraction queries in parallel.
4. Never run pass queries in parallel.
5. Ensure `@kind path-problem` queries specify `@problem.severity error`.
6. Keep an `isBarrier` predicate in query configs even when empty (`none()`).
7. Treat security-hook naming warnings in generated query text as non-blocking unless query execution fails.

Language-specific critical rule:

- Python CodeQL: there is no `Decorator` AST type. Use `getADecorator()` returning `Expr`.
- Python CodeQL: `StrConst` is deprecated. Use modern string literal node classes.

### 3.1 CodeQL compatibility notes

Validated baseline:

- CodeQL CLI: `2.24.x`
- Python pack family: `codeql/python-all 6.1.x`

Compatibility policy:

1. Compile generated queries against the local toolchain before analysis.
2. Prefer `implements DataFlow::ConfigSig` + `TaintTracking::Global<Config>` style.
3. If a newer CodeQL version changes APIs, patch template imports/config signatures first, then regenerate pass queries.
4. Record CLI and pack versions in `iris/exploration/run_manifest.json`.

## 4. Phase 1: Extract and Label

## 4.1 Step 0 - Pre-flight

Goal: verify toolchain and initialize workspace.

### 4.1.1 Verify `codeql` availability

```bash
codeql version
which codeql
```

Fail fast if unavailable.

### 4.1.2 Resolve database metadata

Given `DB=<path-to-codeql-db>`:

```bash
test -d "$DB"
ls "$DB"
```

Inspect metadata file (commonly `codeql-database.yml`):

```bash
DB_META="$DB/codeql-database.yml"
test -f "$DB_META" && cat "$DB_META"
```

Extract language key from metadata if present. If not present, infer from database naming and top-level source layout.

### 4.1.3 Initialize directory tree

```bash
mkdir -p iris/{exploration,extraction,labels,libraries,queries,results,report}
```

### 4.1.4 Write `qlpack.yml`

Create `iris/qlpack.yml`:

```yaml
name: iris/generated
version: 0.0.1
dependencies:
  codeql/<language>-all: "*"
```

Pick `<language>` from detection (`python`, `go`, `java`, `javascript`, `csharp`).

### 4.1.5 Install packs

```bash
cd iris
codeql pack install
```

Do not continue if pack install fails.

### 4.1.6 Record run manifest

Write `iris/exploration/run_manifest.json` with:

- timestamp
- DB path
- detected language (tentative)
- selected passes
- model identifier

This makes runs reproducible.

## 4.2 Step 1 - Explore and detect

Goal: detect language/framework and load only relevant references.

### 4.2.1 Detect language

Detection order:

1. Database metadata language
2. File extensions in repository (`.py`, `.go`, `.java`, `.js/.ts`, `.cs`)
3. Build manifests (`pyproject.toml`, `go.mod`, `pom.xml`, `build.gradle`, `package.json`, `.csproj`)

### 4.2.2 Detect framework

Heuristic examples (non-exhaustive):

- FastAPI: `from fastapi import FastAPI`, `APIRouter`
- Django: `django.urls`, `urlpatterns`, `views.py`
- Flask: `from flask import Flask`, `@app.route`
- Gin: `github.com/gin-gonic/gin`
- Echo: `github.com/labstack/echo/v4`
- Spring: `@RestController`, `@RequestMapping`
- Express: `express()`, `app.get/post/use`
- ASP.NET Core: `WebApplication.CreateBuilder`, `[ApiController]`

Framework confidence scoring (required):

Use additive evidence scoring per framework and normalize to `[0,1]`.

- Import/package evidence: `+0.45`
- Route/decorator/annotation evidence: `+0.30`
- Runtime/bootstrap evidence: `+0.20`
- Directory/layout evidence: `+0.05`

Decision thresholds:

- `>=0.75`: primary framework
- `0.50..0.74`: secondary candidate, include in detection output
- `<0.50`: ignore unless no higher-confidence framework exists

Always persist raw evidence strings with each score.

### 4.2.3 Load references on demand

Always load:

- `references/patterns.md`
- `references/<language>.md`

Then load framework reference(s) if detected:

- `references/<framework>.md`

If no framework match exists:

1. Use language reference to derive source/sink shapes from repository code.
2. Write assumptions to `iris/exploration/detection.json`.

### 4.2.4 Persist detection output

Write `iris/exploration/detection.json` with:

- language
- framework candidates
- confidence score per framework
- evidence snippets (import strings, decorators/annotations)
- reference files loaded

### 4.2.5 Multi-language and multi-framework projects

For polyglot repositories:

1. Create one CodeQL DB per language (recommended) and run Augur independently per DB.
2. Keep per-language outputs isolated, for example `iris-python/`, `iris-go/`, `iris-javascript/`.
3. If cross-service flows matter, aggregate final reports manually in a top-level summary.

For multiple frameworks in one language:

1. Load all matching framework references.
2. Merge framework-specific sink/source signatures during extraction.
3. Keep framework tag metadata in candidate rows to improve LLM labeling context.

## 4.3 Step 2 - Extract candidates

Goal: generate candidate source/sink APIs for LLM labeling.

### 4.3.1 Build extraction query pair

Create:

- `iris/extraction/sources.ql`
- `iris/extraction/sinks.ql`

Preferred template inputs:

- `assets/extraction/extract_sources.ql.tmpl`
- `assets/extraction/extract_sinks.ql.tmpl`
- language starter templates under `assets/extraction/*_sources.ql.tmpl` and `assets/extraction/*_sinks.ql.tmpl`

Queries should select API candidates with metadata columns:

- package/module
- type/receiver/class
- callable name
- argument index (if relevant)
- kind hint (`param`, `return`, `arg`, `receiver`)
- location (file, line)

For route/handler parameter sources, include real parameter index whenever available.

### 4.3.1a Extraction template substitution guide (required)

For generic templates (`extract_sources.ql.tmpl`, `extract_sinks.ql.tmpl`), fill:

- `{{QUERY_NAME}}`, `{{QUERY_DESCRIPTION}}`, `{{QUERY_ID}}`
- `{{LANGUAGE_IMPORTS}}`
- `{{HELPER_PREDICATES}}`
- `{{SOURCE_CLAUSES}}` or `{{SINK_CLAUSES}}`
- `{{SELECT_*}}` placeholders

Language starter selection:

- Python: `assets/extraction/python_sources.ql.tmpl`, `python_sinks.ql.tmpl`
- Go: `assets/extraction/go_sources.ql.tmpl`, `go_sinks.ql.tmpl`
- Java: `assets/extraction/java_sources.ql.tmpl`, `java_sinks.ql.tmpl`
- JavaScript: `assets/extraction/javascript_sources.ql.tmpl`, `javascript_sinks.ql.tmpl`
- C#: `assets/extraction/csharp_sources.ql.tmpl`, `csharp_sinks.ql.tmpl`

Minimum extracted columns to preserve labeling quality:

1. candidate kind
2. callable name
3. flow kind
4. receiver/type hint
5. module/package path
6. arg index (`-1` only when not applicable)
7. file/line

### 4.3.2 Candidate strategy

Collect candidates from both external and internal APIs:

- External libraries likely to receive tainted input or perform dangerous actions
- Internal boundary handlers (HTTP, CLI, queue consumers)
- Data-access and execution APIs

Exclude obvious noise:

- tests and fixtures
- generated code
- pure logging helpers

### 4.3.3 Execute extraction sequentially

Run one query at a time:

```bash
codeql query run iris/extraction/sources.ql \
  --database "$DB" \
  --output iris/extraction/sources.bqrs

codeql query run iris/extraction/sinks.ql \
  --database "$DB" \
  --output iris/extraction/sinks.bqrs
```

Do not use background jobs, `xargs -P`, or parallel workers.

### 4.3.4 Decode BQRS to CSV

```bash
codeql bqrs decode iris/extraction/sources.bqrs --format=csv --output=iris/extraction/sources.csv
codeql bqrs decode iris/extraction/sinks.bqrs --format=csv --output=iris/extraction/sinks.csv
```

### 4.3.5 Summarize extraction

Write `iris/extraction/summary.md`:

- number of unique source candidates
- number of unique sink candidates
- top modules/classes by count
- candidates excluded and why

## 4.4 Step 3 - LLM label

Goal: label candidates for all six passes and produce schema-valid `labels.json`.

### 4.4.1 Labeling inputs

Inputs to LLM per batch:

- CWE pass descriptor
- candidate APIs from CSV
- selected code snippets (usage context)
- framework-specific hints from `references/*.md`

### 4.4.2 Labeling outputs

For each candidate and pass, output:

- role: `source`, `sink`, `sanitizer`, `summary`, or `none`
- confidence in `[0,1]`
- rationale (short)
- metadata required for query generation

### 4.4.3 Suggested prompt contract

System prompt responsibilities:

- classify APIs for a single CWE pass
- prefer conservative recall in pass 1-4
- avoid overlabeling sink APIs for pass 5 unless SQL execution is present
- mark sanitizers only with concrete evidence

User prompt payload fields:

- `pass_id`
- `cwes`
- `language`
- `framework`
- `candidates`
- `context_snippets`
- output must be JSON only

### 4.4.4 Batch policy

- Use batched labeling for scalability
- Keep batch sizes stable (for reproducible costs)
- Re-ask only low-confidence entries below threshold (example: `<0.55`)

### 4.4.5 Output contract

Write `iris/labels/labels.json` conforming to `assets/labels_schema.json`.

Recommended artifacts:

- `iris/labels/labels_raw_pass1.json` ... `labels_raw_pass6.json`
- `iris/labels/label_stats.md`

### 4.4.6 Label quality checks

Before checkpoint:

1. Validate schema.
2. Ensure each enabled pass has at least one sink or document why none exist.
3. Remove obvious duplicates.
4. Verify argument index bounds where available.

## 4.5 CHECKPOINT - Human review gate (mandatory)

Stop here and present a concise summary for approval.

Minimum review payload:

- label counts by pass and role
- top high-risk sink APIs
- top broad source APIs
- sanitizer list
- unresolved/low-confidence items

Approval mechanism (required):

Write `iris/labels/review_decision.json` before Step 4 with:

```json
{
  "approved": true,
  "reviewer": "name-or-handle",
  "timestamp": "ISO-8601",
  "notes": "optional rationale",
  "scope": {
    "passes": [1, 2, 3, 4, 5, 6]
  }
}
```

Do not execute Step 4+ until `approved` is `true`.

## 5. Phase 2: Analyze and Report

## 5.1 Step 4 - Generate libraries

Goal: compile labels into CodeQL library predicates.

Required files:

- `iris/libraries/MySources.qll`
- `iris/libraries/MySinks.qll`
- `iris/libraries/MySanitizers.qll`
- `iris/libraries/MySummaries.qll`

### 5.1.1 Source library requirements

Define a predicate that matches source nodes filtered by pass.

Expected shape:

- accepts a data-flow node
- accepts pass key (for pass-specific query generation)
- matches labeled API signatures

### 5.1.2 Sink library requirements

Define sink predicate similarly with pass key.

### 5.1.3 Sanitizer and summary libraries

- `isBarrier` plumbing uses sanitizer predicate
- `MySummaries` may define extra taint steps for framework glue code

If no sanitizer/summary entries exist, keep predicates defined with `none()` fallback behavior in queries.

### 5.1.4 Generation method

Use deterministic rendering from labels:

1. Group by pass and role.
2. Deduplicate signatures.
3. Emit stable ordering.
4. Include machine-generated header in each file.

### 5.1.5 Scalable library organization

Do not keep one monolithic cascading predicate as the codebase grows.

Use sharded organization:

1. `MySources.qll` and `MySinks.qll` dispatch by pass key.
2. Per-pass helper modules encapsulate signature matching.
3. Optional per-framework helper modules encapsulate wrapper-specific logic.
4. Keep sanitizers and summaries independently sharded to avoid giant predicates.

## 5.2 Step 5 - Run taint queries

Goal: run pass-specific taint tracking queries sequentially.

### 5.2.1 Generate pass queries

Render query files from `assets/taint_query.ql.tmpl`:

- `iris/queries/Pass1_PathTraversal.ql`
- `iris/queries/Pass2_CommandInjection.ql`
- `iris/queries/Pass3_SSRF.ql`
- `iris/queries/Pass4_CodeInjection.ql`
- `iris/queries/Pass5_SQLInjection.ql`
- `iris/queries/Pass6_UnsafeDeserialization.ql`

### 5.2.1a Template substitution guide (required)

`assets/taint_query.ql.tmpl` must be rendered with concrete values before execution.

Required placeholders:

- `{{QUERY_NAME}}`: human-readable pass name
- `{{QUERY_DESCRIPTION}}`: short pass-specific description
- `{{QUERY_ID}}`: stable query id (for example `py/augur/pass1-path-traversal`)
- `{{PRECISION}}`: CodeQL precision label (`low|medium|high|very-high`)
- `{{CWE_PRIMARY}}`: primary CWE id for the pass
- `{{EXTRA_TAGS}}`: newline-prefixed additional CWE tags
- `{{SOURCE_MODULE}}`: module exposing `isSource(node, passKey)`
- `{{SINK_MODULE}}`: module exposing `isSink(node, passKey)`
- `{{SANITIZER_MODULE}}`: module exposing `isBarrier(node, passKey)` (must exist, can resolve to `none()`)
- `{{SUMMARY_MODULE}}`: module exposing `isAdditionalTaintStep(nodeFrom, nodeTo, passKey)`
- `{{CONFIG_NAME}}`: flow configuration module name (for example `Pass1Config`)
- `{{FLOW_MODULE}}`: flow module alias name (for example `Pass1Flow`)
- `{{PASS_KEY}}`: normalized pass key string (for example `path_traversal`)
- `{{RESULT_MESSAGE}}`: result message string
- `{{LANGUAGE_IMPORTS}}`: language-specific import block

Language import substitutions:

- Python:
  - `import python`
  - `import semmle.python.dataflow.new.DataFlow`
  - `import semmle.python.dataflow.new.TaintTracking`
- Go:
  - `import go`
  - `import semmle.go.dataflow.new.DataFlow`
  - `import semmle.go.dataflow.new.TaintTracking`
- Java:
  - `import java`
  - `import semmle.code.java.dataflow.DataFlow`
  - `import semmle.code.java.dataflow.TaintTracking`
- JavaScript/TypeScript:
  - `import javascript`
  - `import semmle.javascript.dataflow.DataFlow`
  - `import semmle.javascript.dataflow.TaintTracking`
- C#:
  - `import csharp`
  - `import semmle.code.csharp.dataflow.DataFlow`
  - `import semmle.code.csharp.dataflow.TaintTracking`

### 5.2.2 Query metadata rules

Each pass query must contain:

- `@kind path-problem`
- `@problem.severity error`
- relevant CWE tags
- imports for language data flow + generated libraries

### 5.2.3 Mandatory barrier hook

Every query config must define `isBarrier` even if empty:

```ql
predicate isBarrier(DataFlow::Node n) { none() }
```

or delegate to sanitizer library that can resolve to empty.

### 5.2.4 Sequential execution only

Run exactly one pass query at a time:

```bash
codeql database analyze "$DB" iris/queries/Pass1_PathTraversal.ql \
  --format=sarifv2.1.0 --output=iris/results/pass1.sarif

codeql database analyze "$DB" iris/queries/Pass2_CommandInjection.ql \
  --format=sarifv2.1.0 --output=iris/results/pass2.sarif

# Repeat through pass6
```

### 5.2.5 Optional decode path

If using `query run` output (`.bqrs`), decode immediately after each run.

### 5.2.6 Runtime logging

Append per-pass runtime and alert counts to `iris/results/run_log.md`.

## 5.3 Step 6 - Filter and report

Goal: reduce noisy findings and produce final markdown report.

### 5.3.1 Run filter script

```bash
python3 scripts/filter_and_report.py \
  --input-dir iris/results \
  --labels iris/labels/labels.json \
  --output iris/report/iris_report.md
```

### 5.3.2 Language-agnostic FP heuristics

Apply these default heuristics:

- Test files -> FP (all passes)
- Migration files -> FP (all passes)
- Path Traversal:
  - admin-config-only path sources -> FP
  - explicit `startswith` guard against base dir -> FP
  - basename extraction and traversal neutralization -> FP
  - explicit `'..'` rejection checks -> FP
- SSRF:
  - admin-configured URLs -> FP
  - OAuth/OIDC fixed endpoints -> FP
  - known search engine endpoint patterns -> FP
- Code Injection:
  - test files only -> FP
  - execution over DB-controlled content remains TP candidate
- SQL Injection:
  - parameterized queries/bound params -> FP

### 5.3.3 Optional baseline comparison

If baseline outputs are available (stock CodeQL):

- compute overlap and delta
- include newly surfaced findings
- include filtered-out baseline-only alerts

### 5.3.4 Report sections

`iris/report/iris_report.md` should include:

1. Scope and runtime
2. Label summary by pass
3. Raw finding counts by pass
4. Heuristic-filtered counts by pass
5. Top likely true positives
6. Rejected findings with reasons
7. Optional baseline comparison
8. Analyst follow-ups

## 6. Data contracts

## 6.1 Candidate row contract

CSV columns (suggested):

- `candidate_id`
- `language`
- `framework`
- `module_or_package`
- `type_or_receiver`
- `callable`
- `arg_index`
- `flow_kind`
- `location`
- `snippet`

## 6.2 Label contract

`labels.json` schema is defined in `assets/labels_schema.json`.

Agent must include at least:

- metadata block (run, model, language)
- pass blocks with cwes/focus
- entries list with role/classification info

## 6.3 Query generation contract

Template placeholders should include:

- pass id/name
- CWE tags
- message string
- module names for generated libraries
- flow configuration name
- flow module alias name
- language import block

## 7. Prompting guidance (LLM)

Use strict JSON response mode when possible.

## 7.1 Labeling prompt template

Provide to model:

- vulnerability focus for this pass
- candidate signatures
- short snippets
- classification rubric

Rubric example:

- `source`: accepts attacker-influenced input boundary
- `sink`: executes, queries, fetches, or deserializes attacker-controlled data
- `sanitizer`: proven neutralization for the pass
- `summary`: helper flow step needed for realistic propagation
- `none`: unrelated

## 7.2 Contextual path triage prompt template

For each alert path, provide:

- source node snippet + location
- intermediate nodes (trim long paths)
- sink node snippet + location
- CWE context

Request JSON:

- `verdict`: `likely_tp` or `likely_fp`
- `reason`
- `source_is_false_positive` (bool)
- `sink_is_false_positive` (bool)
- `confidence`

## 7.3 Determinism guardrails

- fix temperature low (0-0.2)
- ask for concise reasons
- reject non-JSON outputs and re-ask
- preserve original candidates in raw artifacts for audit

## 8. Error handling and recovery

## 8.1 Pack resolution failures

- Re-check dependency name in `qlpack.yml`
- Run `codeql pack install` from the directory containing `qlpack.yml`
- Pin CodeQL version if pack compatibility fails

## 8.2 DB lock/contention errors

Symptoms usually indicate accidental parallel runs.

Recovery:

1. Stop all concurrent CodeQL processes.
2. Re-run failed query alone.
3. Enforce sequential queueing in agent logic.

## 8.3 Query compile errors

Check for:

- missing imports
- unsupported AST classes for language
- invalid barrier/sanitizer references
- wrong dataflow module variant

## 8.4 Security hook warnings

Some hooks may warn about certain function names in query text.

Rule: if query compiles and runs, treat hook warning as false alarm unless organizational policy says otherwise.

## 9. Python-specific pitfalls

- Do not use a non-existent `Decorator` AST class.
- Use decorator expressions via `getADecorator()`.
- Avoid deprecated string literal node classes (for example legacy `StrConst`).
- Keep flow config predicates minimal and explicit.

## 10. Completion checklist

Before delivering results, confirm:

1. `codeql pack install` was executed successfully.
2. Extraction queries executed sequentially.
3. `labels.json` is schema-valid.
4. Human checkpoint approval is recorded.
5. Pass queries executed sequentially.
6. Filtering script produced report output.
7. Report includes TP candidates and FP rationale.

## 11. Minimal command cookbook

```bash
# Step 0
codeql version
mkdir -p iris/{exploration,extraction,labels,libraries,queries,results,report}
cd iris && codeql pack install

# Step 2
codeql query run extraction/sources.ql --database "$DB" --output extraction/sources.bqrs
codeql bqrs decode extraction/sources.bqrs --format=csv --output extraction/sources.csv

# Step 3
# (LLM call by agent)

# Step 5
codeql database analyze "$DB" queries/Pass1_PathTraversal.ql --format=sarifv2.1.0 --output results/pass1.sarif

# Step 6
python3 scripts/filter_and_report.py --input-dir iris/results --labels iris/labels/labels.json --output iris/report/iris_report.md
```

## 12. Extension notes

To add another language/framework:

1. Add `references/<language>.md` or `references/<framework>.md`.
2. Update extraction query generators for that language.
3. Add signature renderers for generated `.qll` predicates.
4. Keep same label schema and report format.

The core workflow remains unchanged.
