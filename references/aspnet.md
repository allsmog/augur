# ASP.NET Core Source/Sink Signatures

Use when C# + ASP.NET Core is detected.

## 1. Detection heuristics

- `WebApplication.CreateBuilder`
- controllers with `[ApiController]` and routing attributes
- minimal API mapping (`MapGet`, `MapPost`, etc.)

## 2. Source patterns

- bound parameters from route/query/body
- `HttpRequest` headers, form values, query collection
- model-bound DTO properties

## 3. Sink patterns

- `System.IO` file/path operations
- process execution APIs
- outbound `HttpClient` request targets
- dynamic code or expression execution
- raw SQL execution APIs
- unsafe serializer usage

## 4. Sanitizer patterns

- input validators with explicit constraints
- safe path canonicalization and allow-list checks
- SQL parameters (`DbParameter`)

## 5. FP heuristics

- unit/integration tests -> FP
- migration scripts -> FP
- parameterized SQL -> FP for pass 5

## 6. Signature cues for extraction

Source candidates:

- `[FromRoute]`, `[FromQuery]`, `[FromBody]`
- `HttpRequest.Query`, `HttpRequest.Form`, `HttpRequest.Headers`
- model-bound DTO fields

Sink candidates:

- `System.IO.File.*` / path-based APIs
- `Process.Start(...)`
- `HttpClient.SendAsync/GetAsync/PostAsync` with dynamic URI
- expression/runtime code APIs
- raw SQL command execution
- insecure deserializer entrypoints

## 7. Minimal APIs and controller parity

Apply same source modeling to:

- classic controllers
- minimal API lambda handlers (`MapGet/MapPost`)

Both expose boundary inputs and should be modeled as sources.

## 8. Layering and summary edges

Typical flow:

- endpoint -> service -> repository -> sink
- endpoint -> helper -> external client

Add summary edges where wrappers pass taint unchanged.

## 9. Pass notes

Path Traversal:

- file upload/download and archive handlers

Command Injection:

- admin diagnostics invoking shell tools

SSRF:

- connectivity testing and URL forwarding utilities

Code Injection:

- dynamic expression execution modules

SQL Injection:

- raw SQL APIs and interpolated command text

Unsafe Deserialization:

- legacy serializer compatibility code

## 10. FP reductions

- test projects and sample apps -> FP
- migration scripts -> FP
- parameterized SQL commands -> FP for pass 5
- fixed trusted service URL sets -> likely FP for SSRF

## 11. Labeling context fields

Include:

- namespace + declaring type
- attribute annotations
- parameter role and index
- sink method overload signature

## 12. CodeQL predicate sketch

```ql
import csharp

predicate isAspNetSource(DataFlow::Node n) {
  exists(Parameter p |
    (
      p.getAnAttribute().getType().getName() = "FromRoute" or
      p.getAnAttribute().getType().getName() = "FromQuery" or
      p.getAnAttribute().getType().getName() = "FromBody"
    ) and
    n.asParameter() = p
  )
}
```

## 13. CodeQL extraction example

```ql
import csharp

predicate aspNetBoundSource(Parameter p) {
  exists(Attribute a |
    a = p.getAnAttribute() and
    (
      a.getType().getName() = "FromRoute" or
      a.getType().getName() = "FromQuery" or
      a.getType().getName() = "FromBody"
    )
  )
}

predicate aspNetSqlSink(InvocationExpr inv) {
  inv.getTarget().getName() = "Execute" or inv.getTarget().getName() = "ExecuteReader"
}
```
