#!/usr/bin/env python3
"""Augur post-hoc false-positive filtering and report generation.

This script is intentionally dependency-light and agent-agnostic.
It accepts SARIF/JSON/CSV findings, applies heuristic filtering rules,
and writes a markdown report.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

PASS_INFO = {
    1: {"name": "Path Traversal", "cwes": ["022", "023", "036", "073"]},
    2: {"name": "Command/Argument Injection", "cwes": ["077", "078", "088"]},
    3: {"name": "SSRF", "cwes": ["918", "099", "610"]},
    4: {"name": "Code Injection", "cwes": ["094", "095"]},
    5: {"name": "SQL Injection", "cwes": ["089"]},
    6: {"name": "Unsafe Deserialization", "cwes": ["502"]},
}

PASS_NAME_TO_ID = {v["name"].lower(): k for k, v in PASS_INFO.items()}

TEST_RE = re.compile(r"(^|/)(test|tests|spec|specs|__tests__|fixtures)(/|$)", re.IGNORECASE)
MIGRATION_RE = re.compile(r"(^|/)(migrations?|alembic|flyway|liquibase|schema_migrations)(/|$)", re.IGNORECASE)

PASS1_FP_PATTERNS = [
    re.compile(r"startswith\s*\(", re.IGNORECASE),
    re.compile(r"os\.path\.basename|path\.basename|filepath\.base", re.IGNORECASE),
    re.compile(r"\b\.\.[/\\]", re.IGNORECASE),
    re.compile(r"reject|deny|block.*\.\.", re.IGNORECASE),
    re.compile(r"admin.*config|configured path|trusted config", re.IGNORECASE),
]

PASS2_FP_PATTERNS = [
    re.compile(r"shell\s*=\s*false", re.IGNORECASE),
    re.compile(r"shell\s*:\s*false", re.IGNORECASE),
    re.compile(r"subprocess\.run\s*\(\s*\[", re.IGNORECASE),
]

PASS2_TP_PATTERNS = [
    re.compile(r"sh\s+-c|bash\s+-c|cmd\s+/c|powershell\s+-command", re.IGNORECASE),
    re.compile(r"[\"']sh[\"']\s*,\s*[\"']-c[\"']", re.IGNORECASE),
    re.compile(r"[\"']bash[\"']\s*,\s*[\"']-c[\"']", re.IGNORECASE),
    re.compile(r"[\"']cmd[\"']\s*,\s*[\"']/c[\"']", re.IGNORECASE),
    re.compile(r"subprocess\.run\s*\(\s*\[\s*[\"'](sh|bash|cmd)[\"']", re.IGNORECASE),
    re.compile(r"os\.system|popen\(|exec\(", re.IGNORECASE),
]

PASS3_FP_PATTERNS = [
    re.compile(r"oauth|oidc", re.IGNORECASE),
    re.compile(r"admin.*config|trusted endpoint|configured url", re.IGNORECASE),
    re.compile(r"google|bing|duckduckgo|search endpoint", re.IGNORECASE),
]

PASS4_FP_PATTERNS = [
    re.compile(r"\beval\s*\(\s*[\"']", re.IGNORECASE),
    re.compile(r"\bexec\s*\(\s*[\"']", re.IGNORECASE),
    re.compile(r"ast\.literal_eval", re.IGNORECASE),
]

PASS5_FP_PATTERNS = [
    re.compile(r"prepared\s+statement|prepare\(", re.IGNORECASE),
    re.compile(r"bindparam|bind parameter|parameterized", re.IGNORECASE),
    re.compile(r"\$[0-9]+|\?|:([a-z_][a-z0-9_]*)", re.IGNORECASE),
]

PASS6_FP_PATTERNS = [
    re.compile(r"yaml\.safe_load|safeloader", re.IGNORECASE),
    re.compile(r"strict[_-]?load|allowlist|type whitelist|type allow-list", re.IGNORECASE),
    re.compile(r"json\.loads.*(schema|validate|pydantic)", re.IGNORECASE),
]

PASS6_TP_PATTERNS = [
    re.compile(r"pickle\.loads|pickle\.load", re.IGNORECASE),
    re.compile(r"yaml\.load(?!\s*\()", re.IGNORECASE),
    re.compile(r"yaml\.load\(", re.IGNORECASE),
    re.compile(r"marshal\.loads|binaryformatter|objectinputstream", re.IGNORECASE),
]

DB_CONTENT_PATTERNS = [
    re.compile(r"from database|db content|database value|persisted payload", re.IGNORECASE),
    re.compile(r"model\.|row\.|record\.|result set", re.IGNORECASE),
]


@dataclass
class Finding:
    pass_id: int
    source_file: str
    line: int
    rule_id: str
    message: str
    snippet: str
    origin_file: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        return f"{self.pass_id}|{self.source_file}|{self.line}|{self.rule_id}"

    def text_blob(self) -> str:
        return " ".join(
            part for part in [self.source_file, self.rule_id, self.message, self.snippet] if part
        ).lower()


@dataclass
class ClassifiedFinding:
    finding: Finding
    verdict: str  # likely_tp | likely_fp | candidate
    reasons: List[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Filter Augur findings and produce markdown report")
    parser.add_argument("--input-dir", required=True, type=Path, help="Directory with SARIF/JSON/CSV findings")
    parser.add_argument("--labels", required=True, type=Path, help="Path to labels.json")
    parser.add_argument("--output", required=True, type=Path, help="Output markdown report path")
    parser.add_argument(
        "--baseline-dir",
        type=Path,
        default=None,
        help="Optional directory containing baseline findings for comparison",
    )
    parser.add_argument(
        "--max-listed",
        type=int,
        default=50,
        help="Maximum findings to list in TP/FP sections",
    )
    return parser.parse_args()


def detect_pass_id(name: str, fallback: Optional[int] = None) -> Optional[int]:
    base = name.lower()
    match = re.search(r"pass\s*([1-6])", base)
    if match:
        return int(match.group(1))
    match = re.search(r"\bcwe[-_ ]?0*([0-9]{2,4})\b", base)
    if match:
        cwe = match.group(1)
        for pass_id, info in PASS_INFO.items():
            if cwe in info["cwes"]:
                return pass_id
    for pass_name, pass_id in PASS_NAME_TO_ID.items():
        if pass_name in base:
            return pass_id
    return fallback


def _safe_line(value: Any) -> int:
    try:
        line = int(value)
        return line if line > 0 else 1
    except Exception:
        return 1


def parse_sarif(path: Path, default_pass: Optional[int]) -> List[Finding]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: List[Finding] = []

    for run in payload.get("runs", []):
        for result in run.get("results", []):
            message = result.get("message", {}).get("text", "")
            rule_id = result.get("ruleId", "unknown")

            locations = result.get("locations") or []
            if not locations:
                findings.append(
                    Finding(
                        pass_id=default_pass or 0,
                        source_file="unknown",
                        line=1,
                        rule_id=rule_id,
                        message=message,
                        snippet="",
                        origin_file=str(path),
                        metadata={"raw": result},
                    )
                )
                continue

            loc = locations[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {})
            region = loc.get("region", {})
            source_file = artifact.get("uri", "unknown")
            line = _safe_line(region.get("startLine", 1))
            snippet = region.get("snippet", {}).get("text", "")
            pass_id = detect_pass_id(message, fallback=default_pass) or detect_pass_id(rule_id, fallback=default_pass) or 0

            findings.append(
                Finding(
                    pass_id=pass_id,
                    source_file=str(source_file),
                    line=line,
                    rule_id=rule_id,
                    message=message,
                    snippet=snippet,
                    origin_file=str(path),
                    metadata={"raw": result},
                )
            )

    return findings


def parse_csv_file(path: Path, default_pass: Optional[int]) -> List[Finding]:
    findings: List[Finding] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            source_file = row.get("file") or row.get("path") or row.get("source_file") or "unknown"
            line = _safe_line(row.get("line") or row.get("start_line") or 1)
            rule_id = row.get("rule_id") or row.get("rule") or "unknown"
            message = row.get("message") or row.get("description") or ""
            snippet = row.get("snippet") or ""
            pass_id_raw = row.get("pass_id")
            pass_id = detect_pass_id(str(pass_id_raw), fallback=default_pass) if pass_id_raw else default_pass
            pass_id = detect_pass_id(f"{rule_id} {message}", fallback=pass_id) or pass_id or 0

            findings.append(
                Finding(
                    pass_id=pass_id,
                    source_file=str(source_file),
                    line=line,
                    rule_id=str(rule_id),
                    message=str(message),
                    snippet=str(snippet),
                    origin_file=str(path),
                    metadata={"row_index": idx},
                )
            )
    return findings


def parse_generic_json(path: Path, default_pass: Optional[int]) -> List[Finding]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows: Iterable[Dict[str, Any]]

    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        rows = payload.get("findings", [])
    else:
        rows = []

    findings: List[Finding] = []
    for idx, row in enumerate(rows, start=1):
        source_file = row.get("file") or row.get("path") or "unknown"
        line = _safe_line(row.get("line", 1))
        rule_id = row.get("rule_id") or row.get("rule") or "unknown"
        message = row.get("message") or ""
        snippet = row.get("snippet") or ""
        pass_id = row.get("pass_id")
        pass_id = detect_pass_id(str(pass_id), fallback=default_pass) if pass_id is not None else default_pass
        pass_id = detect_pass_id(f"{rule_id} {message}", fallback=pass_id) or pass_id or 0

        findings.append(
            Finding(
                pass_id=pass_id,
                source_file=str(source_file),
                line=line,
                rule_id=str(rule_id),
                message=str(message),
                snippet=str(snippet),
                origin_file=str(path),
                metadata={"row_index": idx},
            )
        )

    return findings


def load_findings(input_dir: Path) -> List[Finding]:
    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    findings: List[Finding] = []
    for path in sorted(input_dir.rglob("*")):
        if not path.is_file():
            continue

        suffix = path.suffix.lower()
        default_pass = detect_pass_id(path.name)

        try:
            if suffix == ".sarif":
                findings.extend(parse_sarif(path, default_pass))
            elif suffix == ".csv":
                findings.extend(parse_csv_file(path, default_pass))
            elif suffix == ".json":
                findings.extend(parse_generic_json(path, default_pass))
        except json.JSONDecodeError:
            # Ignore non-JSON files with .json suffix.
            continue

    return findings


def _is_test_or_migration(path_or_text: str) -> Tuple[bool, Optional[str]]:
    normalized = path_or_text.replace("\\", "/")
    if TEST_RE.search(normalized):
        return True, "test file heuristic"
    if MIGRATION_RE.search(normalized):
        return True, "migration file heuristic"
    return False, None


def classify_finding(finding: Finding) -> ClassifiedFinding:
    text = finding.text_blob()
    reasons: List[str] = []

    is_tm, why_tm = _is_test_or_migration(finding.source_file)
    if is_tm:
        reasons.append(why_tm or "test/migration heuristic")
        return ClassifiedFinding(finding=finding, verdict="likely_fp", reasons=reasons)

    if finding.pass_id == 1:
        for pattern in PASS1_FP_PATTERNS:
            if pattern.search(text):
                reasons.append(f"path traversal guard heuristic: `{pattern.pattern}`")
                return ClassifiedFinding(finding=finding, verdict="likely_fp", reasons=reasons)

    if finding.pass_id == 2:
        for pattern in PASS2_TP_PATTERNS:
            if pattern.search(text):
                reasons.append(f"command injection dangerous shell pattern: `{pattern.pattern}`")
                return ClassifiedFinding(finding=finding, verdict="likely_tp", reasons=reasons)
        for pattern in PASS2_FP_PATTERNS:
            if pattern.search(text):
                reasons.append(f"command injection safer invocation heuristic: `{pattern.pattern}`")
                return ClassifiedFinding(finding=finding, verdict="likely_fp", reasons=reasons)

    if finding.pass_id == 3:
        for pattern in PASS3_FP_PATTERNS:
            if pattern.search(text):
                reasons.append(f"SSRF trusted endpoint heuristic: `{pattern.pattern}`")
                return ClassifiedFinding(finding=finding, verdict="likely_fp", reasons=reasons)

    if finding.pass_id == 4:
        for pattern in DB_CONTENT_PATTERNS:
            if pattern.search(text):
                reasons.append("code execution over persisted/DB content heuristic")
                return ClassifiedFinding(finding=finding, verdict="likely_tp", reasons=reasons)
        for pattern in PASS4_FP_PATTERNS:
            if pattern.search(text):
                reasons.append(f"code injection static expression heuristic: `{pattern.pattern}`")
                return ClassifiedFinding(finding=finding, verdict="likely_fp", reasons=reasons)

    if finding.pass_id == 5:
        for pattern in PASS5_FP_PATTERNS:
            if pattern.search(text):
                reasons.append(f"parameterized SQL heuristic: `{pattern.pattern}`")
                return ClassifiedFinding(finding=finding, verdict="likely_fp", reasons=reasons)

    if finding.pass_id == 6:
        for pattern in PASS6_FP_PATTERNS:
            if pattern.search(text):
                reasons.append(f"safe deserialization heuristic: `{pattern.pattern}`")
                return ClassifiedFinding(finding=finding, verdict="likely_fp", reasons=reasons)
        for pattern in PASS6_TP_PATTERNS:
            if pattern.search(text):
                reasons.append(f"unsafe deserialization pattern: `{pattern.pattern}`")
                return ClassifiedFinding(finding=finding, verdict="likely_tp", reasons=reasons)

    # Uncategorized findings default to candidate unless globally filtered.
    reasons.append("no explicit FP/TP heuristic matched")
    return ClassifiedFinding(finding=finding, verdict="candidate", reasons=reasons)


def summarize_labels(labels_path: Path) -> Dict[int, Dict[str, int]]:
    payload = json.loads(labels_path.read_text(encoding="utf-8"))
    summary: Dict[int, Dict[str, int]] = {}

    for p in payload.get("passes", []):
        pass_id = int(p.get("pass_id", 0))
        counts = {"source": 0, "sink": 0, "sanitizer": 0, "summary": 0, "none": 0}
        for entry in p.get("entries", []):
            role = str(entry.get("role", "none"))
            if role in counts:
                counts[role] += 1
            else:
                counts["none"] += 1
        summary[pass_id] = counts

    return summary


def aggregate_by_pass(classified: List[ClassifiedFinding]) -> Dict[int, Dict[str, int]]:
    agg: Dict[int, Dict[str, int]] = {}
    for item in classified:
        pass_id = item.finding.pass_id if item.finding.pass_id in PASS_INFO else 0
        if pass_id not in agg:
            agg[pass_id] = {"raw": 0, "likely_tp": 0, "candidate": 0, "likely_fp": 0}
        agg[pass_id]["raw"] += 1
        agg[pass_id][item.verdict] += 1
    return agg


def compare_baseline(
    current: List[ClassifiedFinding],
    baseline_findings: List[Finding],
) -> Dict[str, int]:
    current_set = {item.finding.fingerprint() for item in current}
    baseline_set = {f.fingerprint() for f in baseline_findings}
    return {
        "current_total": len(current_set),
        "baseline_total": len(baseline_set),
        "only_current": len(current_set - baseline_set),
        "only_baseline": len(baseline_set - current_set),
        "overlap": len(current_set & baseline_set),
    }


def render_markdown(
    output_path: Path,
    labels_summary: Dict[int, Dict[str, int]],
    classified: List[ClassifiedFinding],
    per_pass: Dict[int, Dict[str, int]],
    baseline_summary: Optional[Dict[str, int]],
    max_listed: int,
) -> None:
    ts = dt.datetime.now(dt.timezone.utc).isoformat()
    likely_tp = [x for x in classified if x.verdict == "likely_tp"]
    likely_fp = [x for x in classified if x.verdict == "likely_fp"]
    candidates = [x for x in classified if x.verdict == "candidate"]

    lines: List[str] = []
    lines.append("# Augur IRIS Report")
    lines.append("")
    lines.append(f"Generated at: `{ts}`")
    lines.append("")

    lines.append("## Label Summary")
    lines.append("")
    lines.append("| Pass | Focus | Sources | Sinks | Sanitizers | Summaries | None |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
    for pass_id in sorted(labels_summary):
        counts = labels_summary[pass_id]
        focus = PASS_INFO.get(pass_id, {}).get("name", "unknown")
        lines.append(
            f"| {pass_id} | {focus} | {counts['source']} | {counts['sink']} | {counts['sanitizer']} | {counts['summary']} | {counts['none']} |"
        )

    lines.append("")
    lines.append("## Finding Counts")
    lines.append("")
    lines.append("| Pass | Focus | Raw | Likely TP | Candidate | Likely FP |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: |")

    for pass_id in sorted(per_pass):
        focus = PASS_INFO.get(pass_id, {}).get("name", "unknown")
        stats = per_pass[pass_id]
        lines.append(
            f"| {pass_id} | {focus} | {stats['raw']} | {stats['likely_tp']} | {stats['candidate']} | {stats['likely_fp']} |"
        )

    lines.append("")
    lines.append("## Top Likely True Positives")
    lines.append("")
    if not likely_tp:
        lines.append("No findings matched TP-promoting heuristics.")
    else:
        for item in likely_tp[:max_listed]:
            f = item.finding
            lines.append(
                f"- `pass{f.pass_id}` `{f.source_file}:{f.line}` `{f.rule_id}`: {f.message.strip() or 'No message'}"
            )
            lines.append(f"  - Reason: {item.reasons[0]}")

    lines.append("")
    lines.append("## Candidate Findings (Need Analyst Review)")
    lines.append("")
    if not candidates:
        lines.append("No unresolved candidates.")
    else:
        for item in candidates[:max_listed]:
            f = item.finding
            lines.append(
                f"- `pass{f.pass_id}` `{f.source_file}:{f.line}` `{f.rule_id}`: {f.message.strip() or 'No message'}"
            )
            lines.append(f"  - Reason: {item.reasons[0]}")

    lines.append("")
    lines.append("## Filtered as Likely False Positives")
    lines.append("")
    if not likely_fp:
        lines.append("No findings matched FP heuristics.")
    else:
        for item in likely_fp[:max_listed]:
            f = item.finding
            lines.append(
                f"- `pass{f.pass_id}` `{f.source_file}:{f.line}` `{f.rule_id}`: {f.message.strip() or 'No message'}"
            )
            lines.append(f"  - Reason: {item.reasons[0]}")

    if baseline_summary is not None:
        lines.append("")
        lines.append("## Baseline Comparison")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("| --- | ---: |")
        for key in ["current_total", "baseline_total", "overlap", "only_current", "only_baseline"]:
            lines.append(f"| {key} | {baseline_summary.get(key, 0)} |")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()

    findings = load_findings(args.input_dir)
    classified = [classify_finding(f) for f in findings]
    labels_summary = summarize_labels(args.labels)
    per_pass = aggregate_by_pass(classified)

    baseline_summary = None
    if args.baseline_dir:
        baseline_findings = load_findings(args.baseline_dir)
        baseline_summary = compare_baseline(classified, baseline_findings)

    render_markdown(
        output_path=args.output,
        labels_summary=labels_summary,
        classified=classified,
        per_pass=per_pass,
        baseline_summary=baseline_summary,
        max_listed=args.max_listed,
    )


if __name__ == "__main__":
    main()
