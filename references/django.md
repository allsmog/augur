# Django Source/Sink Signatures

Use when Python + Django is detected.

## 1. Detection heuristics

- `django` imports
- `urlpatterns` and `path()/re_path()` declarations
- class-based views (`View`, `APIView`)

## 2. Source patterns

- `request.GET`, `request.POST`, `request.body`
- route parameters
- headers/cookies/session-derived user input
- DRF serializer input fields

## 3. Sink patterns

- file operations using request-derived paths
- command execution from view/service data
- outbound HTTP requests with user-influenced URL
- template/code evaluation in dynamic contexts
- raw SQL execution (`cursor.execute`, `.raw`)

## 4. Sanitizer patterns

- `safe_join`-style path guards
- URL/domain allow-list checks
- parameterized SQL usage

## 5. FP heuristics

- migration files -> FP
- tests -> FP
- parameterized ORM/SQL -> FP for pass 5

## 6. Notes

Django apps often pass request data through forms/serializers; use summary edges for helper methods.

## 7. Signature cues for extraction

High-value source expressions:

- `request.GET.get(...)`
- `request.POST.get(...)`
- `request.headers.get(...)`
- `request.COOKIES.get(...)`
- serializer `.validated_data[...]`

High-value sinks:

- `open(...)`, `Path(...)`, archive extraction helpers
- `subprocess.run(...)`, `os.system(...)`
- `requests.get/post/request(...)`
- `eval(...)`, `exec(...)`
- `cursor.execute(...)`, `.raw(...)`

## 8. Middleware and auth interactions

Model middleware as contextual information, not automatic sanitization:

- auth middleware limits attacker identity, not input trust
- CSRF middleware does not sanitize sink payload content
- serializer validation may constrain shape but not exploitability semantics

## 9. Summary edge candidates

Add summary edges for helper chains such as:

- view -> serializer helper -> service -> sink
- middleware-enriched request object -> business utility -> sink
- form cleaning wrappers that pass data through unchanged

## 10. Pass notes

Path Traversal:

- focus on file manager endpoints and download handlers
- check whether `safe_join` or explicit containment checks exist

Command Injection:

- focus admin/maintenance endpoints running shell tooling

SSRF:

- focus URL preview/import/proxy endpoints
- operator-configured endpoints may be FP

Code Injection:

- focus custom expression/template execution helpers

SQL Injection:

- focus `.raw` and custom SQL string builders
- parameterized queries lower risk

Unsafe Deserialization:

- focus custom data import endpoints and session/token parsing helpers

## 11. Minimal prompt payload additions

When labeling Django candidates, include:

- view type (function/class-based)
- route pattern
- serializer/form class involved
- ORM/raw SQL context

## 12. Review checklist

- Candidate APIs mapped to concrete locations.
- Duplicates removed by fully qualified callable + arg index.
- Pass 5 labels distinguish raw SQL from parameterized ORM operations.

## 13. CodeQL predicate sketch

```ql
import python

predicate isDjangoSource(DataFlow::Node n) {
  exists(Attribute a |
    (a.getName() = "GET" or a.getName() = "POST") and
    n.asExpr() = a
  )
}
```

## 14. CodeQL extraction example

```ql
import python

predicate djangoRequestSource(Attribute a) {
  a.getObject().toString() = "request" and
  (a.getName() = "GET" or a.getName() = "POST" or a.getName() = "body")
}

predicate djangoSqlSink(Call c) {
  c.getFunc().toString().regexpMatch(".*\\.(execute|raw)$")
}
```
