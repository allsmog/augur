# Echo Source/Sink Signatures

Use when Go + Echo is detected.

## 1. Detection heuristics

- import `github.com/labstack/echo/v4`
- handlers using `echo.Context`

## 2. Source patterns

- `c.Param`, `c.QueryParam`, form values
- bound request structs
- headers/cookies

## 3. Sink patterns

- file open/write operations with tainted path
- command execution wrappers
- HTTP client calls with dynamic URL
- SQL raw execution

## 4. Sanitizer patterns

- path and URL validation helpers
- SQL bind parameter APIs

## 5. FP heuristics

- test code -> FP
- migrations -> FP

## 6. Signature cues for extraction

Source-like operations:

- `c.Param(...)`
- `c.QueryParam(...)`
- `c.FormValue(...)`
- body bind/decode helpers

Sink-like operations:

- path/file I/O calls using user-controlled path
- command execution wrappers
- HTTP client requests with dynamic URLs
- raw SQL execution calls

## 7. Wrapper patterns

Echo services often funnel input through small helper layers.

Add summary edges for:

- handler -> validator -> service -> sink
- handler -> mapper -> repository -> sink

## 8. Pass notes

Path Traversal:

- upload/download and archive extraction utilities

Command Injection:

- devops/maintenance endpoints invoking shell commands

SSRF:

- connectivity check endpoints and URL proxy handlers

Code Injection:

- dynamic scripting hooks in plugin subsystems

SQL Injection:

- custom query builders in repository layer

Unsafe Deserialization:

- custom import pipelines and binary decode handlers

## 9. FP reductions

- tests, mocks, fixture endpoints -> FP
- trusted static endpoint lists -> likely FP for SSRF
- parameterized DB calls -> FP for SQL pass

## 10. Labeling context fields

Include:

- handler method signature
- route/method
- argument index and expected content type
- direct sink call snippet

## 11. CodeQL predicate sketch

```ql
import go

predicate isEchoSource(DataFlow::Node n) {
  exists(CallExpr c |
    c.getCalleeExpr().toString().regexpMatch(".*\\.(Param|QueryParam|FormValue)$") and
    n.asExpr() = c
  )
}
```

## 12. CodeQL extraction example

```ql
import go

predicate echoRequestSource(CallExpr c) {
  c.getCalleeExpr().toString().regexpMatch(".*\\.(Param|QueryParam|FormValue)$")
}

predicate echoSsrfSink(CallExpr c) {
  c.getCalleeExpr().toString().regexpMatch(".*\\.(Get|Post|Do)$")
}
```
