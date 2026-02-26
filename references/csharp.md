# C# CodeQL Patterns

Use this reference when detected language is C#.

## 1. Detection

Indicators:

- `.csproj` / `.sln`
- ASP.NET Core hosting setup
- controllers with routing attributes

## 2. Source families

- ASP.NET request params/query/body/header/cookie
- route values and model-bound properties
- queue/message payload handlers
- config values with external influence

## 3. Sink families

- filesystem APIs (`System.IO`)
- command/process execution (`System.Diagnostics.Process`)
- outbound HTTP requests (`HttpClient`, custom wrappers)
- dynamic code expression/execution APIs
- SQL execution (`DbCommand`, raw SQL methods)
- unsafe deserialization patterns (`BinaryFormatter`-style legacy, insecure serializers)

## 4. Framework crossover

If ASP.NET Core detected, load `references/aspnet.md`.

## 5. Type precision

C# signatures support strong matching by:

- namespace
- declaring type
- method/property
- parameter list

Prefer fully qualified signatures in labels and qll generation.

## 6. Sanitizer patterns

- canonicalized path checks
- command allow-list validation
- URL host/scheme validation
- SQL parameterized commands
- serializer safety options/type restrictions

## 7. Extraction guidance

Capture controller and service layer candidates, including:

- parameter sources from routed endpoints
- dangerous API calls in business/util layers
- helper wrappers that forward taint

## 8. Pass-specific notes

- path traversal appears in upload/download tooling
- command injection often hides in admin diagnostic utilities
- SSRF common in webhook/test connectivity features
- SQL injection in raw query shortcuts
- deserialization issues in legacy compatibility code

## 9. FP heuristics

- test projects/files -> FP
- migration scripts -> FP
- parameterized DB operations -> FP for SQL injection pass

## 10. Validation checklist

- Labels preserve namespace/type info.
- Generated predicates target correct overloads.
- Pass queries include correct CWE tags and severity metadata.

## 11. Signature cues for extraction

Source signatures:

- `HttpRequest.Query[...]`, `Form[...]`, `Headers[...]`
- route/body-bound controller arguments
- minimal API lambda parameters

Sink signatures:

- `System.IO` path/file APIs
- `Process.Start`
- `HttpClient` request URI parameters
- dynamic expression/code execution APIs
- raw SQL execution methods
- deserialization APIs with unsafe settings

## 12. Summary edges

Add summary edges for:

- endpoint -> service -> repository pipelines
- helper wrappers around command/http/sql/file sinks
- DTO mapping functions forwarding tainted fields

## 13. Validation caveats

- data annotations constrain format but may not neutralize exploit payloads
- authorization attributes do not sanitize values

## 14. Prompt context fields

Include:

- namespace/type/method signature
- attribute annotations
- argument role and index
- sink overload and call-site snippet

## 15. Review checklist

- overload resolution is stable in generated signatures
- sink positions are accurate for dangerous arguments
- SQL pass distinguishes parameterized commands from interpolated SQL text
