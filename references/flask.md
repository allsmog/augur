# Flask Source/Sink Signatures

Use when Python + Flask is detected.

## 1. Detection heuristics

- `from flask import Flask, request`
- `@app.route` decorators

## 2. Source patterns

- `request.args`, `request.form`, `request.json`
- path variables in route handlers
- headers and cookies

## 3. Sink patterns

- filesystem operations with request-derived path
- `subprocess`/`os.system` usage
- outbound HTTP with user-controlled URL
- dynamic eval/template execution
- raw SQL execution

## 4. Sanitizer patterns

- canonical path checks + base dir constraints
- strict URL validation
- bind parameters for SQL

## 5. FP heuristics

- tests and tooling scripts -> FP
- migration-like scripts -> FP

## 6. Signature cues for extraction

High-value sources:

- `request.args.get(...)`
- `request.form.get(...)`
- `request.get_json(...)`
- `request.headers.get(...)`
- `request.cookies.get(...)`

High-value sinks:

- filesystem APIs: `open`, path join + file I/O
- process execution: `subprocess.*`, `os.system`
- outbound HTTP: `requests.*`, `httpx.*`
- dynamic exec: `eval`, `exec`, template compilation
- SQL execution: cursor/connection `.execute`

## 7. Blueprint and wrapper considerations

Flask apps frequently route through blueprints and thin wrappers.

Capture wrapper flows:

- route function -> service layer -> sink
- shared helper modules transforming request fields
- decorator-based wrappers that forward user inputs

## 8. Pass-specific reminders

Path Traversal:

- file upload/download endpoints dominate risk
- normalize path and enforce base-dir checks

Command Injection:

- shell invocation in admin endpoints is high signal

SSRF:

- webhook verification and URL fetch helpers are common sinks

Code Injection:

- custom expression processing features need close inspection

SQL Injection:

- raw SQL formatting helpers need summary edges

Unsafe Deserialization:

- import/export and plugin state loaders are key

## 9. FP reductions

- test-only harness endpoints -> FP
- static operator-configured URLs -> likely FP for SSRF
- SQL binds/prepared patterns -> likely FP for pass 5

## 10. Labeling prompt additions

Include in per-candidate context:

- blueprint/module name
- route path and HTTP method
- whether function is async
- downstream sink call chain depth

## 11. Review checklist

- Confirm sink arg index points at tainted payload position.
- Confirm sanitizer labels correspond to explicit neutralization, not just parsing.

## 12. CodeQL predicate sketch

```ql
import python

predicate isFlaskRequestSource(DataFlow::Node n) {
  exists(Attribute a |
    a.getObject().toString() = "request" and
    (a.getName() = "args" or a.getName() = "form" or a.getName() = "json") and
    n.asExpr() = a
  )
}
```

## 13. CodeQL extraction example

```ql
import python

predicate flaskRequestSource(Attribute a) {
  a.getObject().toString() = "request" and
  (a.getName() = "args" or a.getName() = "form" or a.getName() = "json")
}

predicate flaskCommandSink(Call c) {
  c.getFunc().toString().regexpMatch(".*\\.(run|Popen)$")
  or
  c.getFunc().toString() = "os.system"
}
```
