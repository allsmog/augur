# Augur

Augur is an agent-agnostic skill package that operationalizes IRIS (ICLR 2025) as a reusable neuro-symbolic SAST workflow.

The package is not tied to any SDK, CLI wrapper, or agent runtime. Any agent that can:

1. Read files
2. Run shell commands
3. Call an LLM

can execute Augur end to end.

## What Augur contains

- `WORKFLOW.md`: the execution contract (two phases, checkpointed workflow)
- `references/`: CodeQL and framework guidance loaded on-demand
- `assets/`: reusable schema/template assets (taint + extraction templates)
- `scripts/`: deterministic helper scripts
- `examples/`: worked end-to-end example artifacts
- `adapters/claude-code/SKILL.md`: optional frontend for Claude Code

## Scope

Augur focuses on:

- API candidate extraction with CodeQL
- LLM-based source/sink/sanitizer labeling
- CodeQL library/query generation
- Sequential taint analysis runs per CWE pass
- Post-hoc false-positive triage and markdown reporting

## Supported languages and frameworks

Languages:

- Python
- Go
- Java
- JavaScript/TypeScript
- C#

Framework references included:

- FastAPI, Django, Flask
- Gin, Echo
- Spring Boot
- Express
- ASP.NET Core

## Quick start (any agent)

1. Read `WORKFLOW.md`.
2. Run Step 0 (pre-flight) before writing or executing queries.
3. Load `references/<language>.md` and `references/<framework>.md` based on detection.
4. Execute extraction and taint queries sequentially.
5. Generate `labels/labels.json` using `assets/labels_schema.json`.
6. Pause at checkpoint for human review.
7. Resume Phase 2, run analysis, then call `scripts/filter_and_report.py`.

## Repository layout

```text
augur/
├── README.md
├── WORKFLOW.md
├── references/
├── assets/
├── scripts/
├── examples/
└── adapters/
```

## Design principles

- Agent-agnostic: no runtime lock-in
- Deterministic shell workflow around probabilistic labeling
- Human checkpoint between inference and exploitation
- Sequential execution for CodeQL DB safety
- Explicit artifact contracts between steps
