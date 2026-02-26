# Python CodeQL Patterns and Pitfalls

Use this reference when detected language is Python.

## 1. Core imports

Common imports for Python taint work:

- `import python`
- `import semmle.python.dataflow.new.DataFlow`
- `import semmle.python.dataflow.new.TaintTracking`

When writing path queries, include the path graph import compatible with your DataFlow module setup.

## 2. Python extraction focus

Prioritize candidate extraction from:

- request handlers (FastAPI/Django/Flask)
- file APIs (`open`, `Path`, `os.path`, `shutil`)
- process APIs (`subprocess`, `os.system`, `pexpect`)
- URL fetchers (`requests`, `httpx`, `urllib`)
- dynamic execution (`eval`, `exec`, template compilation)
- SQL execution (`cursor.execute`, ORM raw SQL)
- deserialization (`pickle`, `yaml.load`, `marshal`, unsafe JSON hooks)

## 3. Source patterns

Common Python source families:

- HTTP request path/query/body/header/cookie values
- function parameters of externally exposed handlers
- environment variables in security-sensitive flows
- CLI args (`argparse`, `sys.argv`) in service-mode tools
- DB content reused into command/eval sinks

## 4. Sink patterns by pass

Pass 1 (path traversal):

- `open(path, ...)`, `Path(path)`, filesystem operations using user-controlled path
- archive extraction destination handling

Pass 2 (command/argument injection):

- `subprocess.run`, `Popen`, `check_output`, `os.system`, `os.popen`

Pass 3 (SSRF):

- `requests.get/post/request`, `httpx.Client.request`, `urllib.request.urlopen`

Pass 4 (code injection):

- `eval`, `exec`, dynamic compilation/template engines

Pass 5 (SQL injection):

- raw SQL execution with string interpolation/concatenation

Pass 6 (unsafe deserialization):

- `pickle.loads/load`, `yaml.load` with unsafe loader, custom object hooks

## 5. Sanitizer patterns

Path traversal sanitizers:

- canonicalize and verify base directory containment
- explicit rejection of `..`
- basename-only extraction when semantics allow

Command sanitizers:

- arg list invocation avoiding shell parsing
- strict allow-list validation for command and parameters

SSRF sanitizers:

- scheme/domain allow-lists
- private-IP blocking or URL resolver checks

SQL sanitizers:

- parameterized queries and bind params

Deserialization sanitizers:

- safe loaders, type allow-list, strict schema decode

## 6. AST and call-shape notes

Use robust signature matching:

- module + function name
- receiver type + method name
- argument index semantics

For wrappers/utilities, emit summary steps in `MySummaries.qll`.

## 7. Critical Python pitfalls

### 7.1 Decorator nodes

There is no standalone `Decorator` type in Python CodeQL APIs.

Use accessor methods like `getADecorator()` (returning expression nodes), and inspect decorator expressions directly.

### 7.2 String literal deprecations

Avoid legacy classes such as deprecated `StrConst` in modern query code.

Prefer currently supported literal classes/predicates in your installed CodeQL version.

### 7.3 Dynamic dispatch ambiguity

Python call targets can be ambiguous.

Mitigation:

- constrain module/import usage
- constrain receiver type where possible
- constrain argument count and literal patterns

### 7.4 Over-broad sources

Marking every function parameter as a source creates unusable alert volume.

Restrict to externally reachable handlers and integration boundaries.

## 8. Extraction query hints

Source extraction heuristics:

- functions with framework route decorators
- reads from request-like objects
- parser/deserializer entrypoints

Sink extraction heuristics:

- calls into known dangerous modules/APIs
- method invocations with risky semantics
- argument positions that carry user-controlled values

Output row must include enough metadata for deterministic qll generation.

## 9. Library generation tips

For each label entry:

- map signature to node predicate in generated `.qll`
- include pass key checks so one file can serve all passes
- keep generated predicates sorted and deduplicated

Always include `isBarrier` handling in final queries, even if no sanitizers were labeled.

## 10. FastAPI crossover

If FastAPI is detected, also load `references/fastapi.md`.

FastAPI-specific additions usually raise recall significantly:

- path/query/body extraction APIs
- dependency injection wrappers
- async handler boundaries

## 11. False-positive heuristics to apply later

Global:

- test files -> FP
- migration files -> FP

Pass-specific:

- path traversal guards (`startswith`, canonical path checks, basename-only) -> likely FP
- SSRF admin-config endpoint usage -> likely FP
- SQL bind params -> likely FP

## 12. Quick validation checklist

Before phase handoff:

1. Source and sink candidate CSVs are non-empty (or justified).
2. `labels.json` includes Python signatures with valid arg indices.
3. Generated Python queries parse with your local CodeQL pack.
4. Query metadata uses `@kind path-problem` and `@problem.severity error`.
