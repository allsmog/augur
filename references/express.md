# Express Source/Sink Signatures

Use when JavaScript/TypeScript + Express is detected.

## 1. Detection heuristics

- `const express = require('express')` or ESM equivalent
- route handler patterns: `app.get/post/use`, `router.<method>`

## 2. Source patterns

- `req.params`, `req.query`, `req.body`
- headers/cookies
- multipart upload fields

## 3. Sink patterns

- `fs` operations with user path
- `child_process` execution
- outbound HTTP requests using dynamic URL
- dynamic eval/template usage
- SQL raw query methods

## 4. Sanitizer patterns

- strong validator middleware with constrained schemas
- safe path normalization and root checks
- parameterized SQL APIs

## 5. FP heuristics

- tests/specs -> FP
- migration/seeder scripts -> FP

## 6. Signature cues for extraction

Source candidates:

- `req.params.*`
- `req.query.*`
- `req.body.*`
- `req.headers[...]`
- `req.cookies[...]`

Sink candidates:

- `fs.readFile/writeFile/open` with tainted path
- `child_process.exec/execFile/spawn`
- `fetch/axios/request` with dynamic URL
- `eval`, `Function`, vm execution APIs
- raw SQL query methods

## 7. Middleware and wrapper flows

Common data movement patterns:

- middleware attaches derived values to `req`
- route -> controller -> service -> repository
- utility modules wrap dangerous sinks

Add summary steps when taint crosses these wrappers.

## 8. Pass notes

Path Traversal:

- static file endpoints and download helpers

Command Injection:

- shell-based utility endpoints and CLI adapters

SSRF:

- URL preview, import, webhook forwarding

Code Injection:

- template/evaluator features and plugin runtimes

SQL Injection:

- ORM escape hatches with raw SQL strings

Unsafe Deserialization:

- custom parser/import routines

## 9. FP reductions

- test/spec fixtures -> FP
- migrations/seeding scripts -> FP
- parameterized query APIs -> FP for SQL pass
- static operator-maintained URL maps -> likely FP for SSRF

## 10. Labeling context fields

Include:

- route and method
- middleware chain notes
- sink signature and argument index
- whether input passed through validation schema

## 11. CodeQL predicate sketch

```ql
import javascript

predicate isExpressSource(DataFlow::Node n) {
  exists(PropAccess pa |
    pa.getBase().toString() = "req" and
    (
      pa.getPropertyName() = "params" or
      pa.getPropertyName() = "query" or
      pa.getPropertyName() = "body"
    ) and
    n.asExpr() = pa
  )
}
```
