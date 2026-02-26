# Gin Source/Sink Signatures

Use when Go + Gin is detected.

## 1. Detection heuristics

- import `github.com/gin-gonic/gin`
- handler functions with `*gin.Context`

## 2. Source patterns

- `c.Param(...)`, `c.Query(...)`, `c.PostForm(...)`
- JSON body binding into structs
- headers and cookies

## 3. Sink patterns

- filesystem path APIs
- `os/exec` and shell wrappers
- outbound HTTP requests
- raw SQL queries
- unsafe deserialization points

## 4. Sanitizer patterns

- validation middleware with strict constraints
- safe path normalization and containment checks
- SQL parameterization

## 5. FP heuristics

- tests/mocks -> FP
- migration SQL -> FP for pass 5

## 6. Signature cues for extraction

Source-like operations:

- `c.Param(...)`
- `c.Query(...)`
- `c.PostForm(...)`
- `c.Bind(...)`, `ShouldBindJSON(...)`
- header/cookie getter methods

Sink-like operations:

- file operations with path arg from context
- `exec.Command(...)`, `exec.CommandContext(...)`
- outbound HTTP client request constructors
- raw SQL execution (`Exec`, `Query`, `QueryRow`)

## 7. Middleware and validation handling

Treat middleware as context, not automatic sanitizer:

- binding/validation may constrain types but not all exploit vectors
- auth middleware reduces actor set but not taint trust boundary

## 8. Summary edge candidates

Important helper chains:

- handler -> request DTO -> service -> repository -> sink
- handler -> utility formatter -> command/sql/http sink

## 9. Pass notes

Path Traversal:

- static file serving and archive operations are common

Command Injection:

- shell wrappers using `sh -c` amplify risk

SSRF:

- URL fetch/proxy endpoints are common

Code Injection:

- script/template plugin hooks are uncommon but high impact

SQL Injection:

- focus string-built query helpers

Unsafe Deserialization:

- focus decode paths with dynamic type assertions

## 10. FP reductions

- test/mocks and fixture packages -> FP
- migration scripts -> FP
- clearly parameterized DB calls -> FP for pass 5

## 11. Labeling context fields

Include:

- package + receiver type
- handler route
- argument index semantics
- downstream callee signature

## 12. CodeQL predicate sketch

```ql
import go

predicate isGinSource(DataFlow::Node n) {
  exists(CallExpr c |
    c.getCalleeExpr().toString().regexpMatch(".*\\.(Param|Query|PostForm)$") and
    n.asExpr() = c
  )
}
```

## 13. CodeQL extraction example

```ql
import go

predicate ginRequestSource(CallExpr c) {
  c.getCalleeExpr().toString().regexpMatch(".*\\.(Param|Query|PostForm)$")
}

predicate ginCommandSink(CallExpr c) {
  c.getCalleeExpr().toString().regexpMatch(".*exec\\.Command(Context)?$")
}
```
