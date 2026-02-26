# FastAPI Source/Sink Signatures

Use this file when Python + FastAPI is detected.

## 1. Framework detection heuristics

Positive indicators:

- `from fastapi import FastAPI`
- `from fastapi import APIRouter`
- route decorators: `@app.get`, `@app.post`, `@router.<method>`
- dependency injection via `Depends(...)`
- request class imports from `fastapi` or `starlette`

If at least two indicators appear, treat framework as FastAPI.

## 2. Source modeling

High-confidence sources:

- path parameters in route handlers
- query parameters
- request body/Pydantic model fields
- header/cookie values
- file upload metadata/content (`UploadFile`)

Useful source signatures:

- handler formal parameters in route-decorated functions
- `Request.query_params.get(...)`
- `Request.path_params.get(...)`
- `Request.headers.get(...)`
- `Request.cookies.get(...)`
- `await request.json()` / body readers

Medium-confidence sources:

- dependency-returned values from auth/context providers
- websocket messages in endpoint handlers

## 3. Sink modeling by pass

Pass 1 path traversal sinks:

- filesystem APIs receiving route/body/query values
- archive extraction destinations derived from request data

Pass 2 command injection sinks:

- process execution APIs where args derive from request fields

Pass 3 SSRF sinks:

- outbound HTTP client calls with URL from request/dependency value

Pass 4 code injection sinks:

- dynamic eval/exec/template execution over request data

Pass 5 SQL injection sinks:

- raw SQL text built from request fields and executed directly

Pass 6 unsafe deserialization sinks:

- unsafe deserialization from request payloads/files

## 4. Auth and middleware context

Potential de-risking context:

- strict auth gating plus admin-only settings
- middleware normalizing/canonicalizing user paths
- validation models that enforce constrained enums/patterns

Do not auto-mark as sanitized solely because Pydantic model exists.

## 5. Common wrapper flows

FastAPI codebases often wrap logic via service layers.

Add summary edges when data flows:

- handler -> service method -> utility -> sink
- dependency provider -> handler arg -> sink
- request parser helpers -> downstream call

## 6. Route decorator handling

When collecting internal API sources:

- detect functions with route decorators
- mark parameters as potential source candidates
- include route method/path metadata in extraction output

For Python CodeQL, inspect decorator expressions via decorator accessors (no standalone `Decorator` AST type).

## 7. False-positive heuristics (FastAPI-specific)

Path traversal:

- values loaded only from trusted admin settings files -> likely FP
- explicit canonical path containment checks -> likely FP

SSRF:

- fixed OAuth/OIDC endpoints configured by operator -> likely FP
- known static search engine URLs -> likely FP

SQL injection:

- parameter binding in SQLAlchemy/text execution -> likely FP

Code injection:

- tests using eval-style helpers -> FP

## 8. Extraction fields to include

For each candidate include:

- module path
- function name
- route decorator (if any)
- parameter name/index
- candidate role hint
- sink/source code snippet
- file and line

These fields improve LLM label quality and reproducibility.

## 9. FastAPI-specific sanitizer candidates

Potential sanitizers to label cautiously:

- path normalization + base-dir enforcement helpers
- URL validator enforcing protocol/domain allow-list
- explicit shell command allow-list validators
- SQL parameterization wrappers

Only classify as sanitizer when neutralization is explicit and verifiable.

## 10. Practical prompt hints

For LLM labeling prompts, include route context:

- HTTP method
- route path
- parameter source channel (path/query/body/header/cookie)
- downstream API use

This context reduces source/sink misclassification.

## 11. Known risk clusters in FastAPI apps

- file download/upload endpoints
- webhook dispatch endpoints
- admin tooling endpoints
- dynamic query/report builders
- plugin/script execution endpoints

Bias extraction coverage toward these clusters first.

## 12. Minimal quality checks

- At least one source candidate category per active endpoint family.
- Sink candidates cover all enabled passes where relevant APIs exist.
- Framework wrappers are represented in summary edges if direct flow is broken.

## 13. CodeQL predicate sketch

```ql
import python

predicate isFastApiHandler(Function f) {
  exists(Expr d | d = f.getADecorator() and d.toString().regexpMatch(".*\.(get|post|put|patch|delete)\\(.*"))
}

predicate isFastApiSource(DataFlow::Node n) {
  exists(Call c | c.getFunc().toString() = "Query" and n.asExpr() = c)
}
```

## 14. CodeQL extraction example

```ql
import python

predicate fastApiRouteHandler(Function f) {
  exists(Expr d | d = f.getADecorator() and d.toString().regexpMatch(".*\\.(get|post|put|patch|delete)\\(.*"))
}

predicate fastApiParamSource(Parameter p, int i) {
  exists(Function f |
    fastApiRouteHandler(f) and
    p = f.getArg(i) and
    not p.isSelf()
  )
}

predicate fastApiSsrfSink(Call c) {
  c.getFunc().toString().regexpMatch(".*\\.(get|post|request)$")
}
```
