# Java CodeQL Patterns

Use this reference when detected language is Java.

## 1. Detection

Indicators:

- `pom.xml`, `build.gradle`, `build.gradle.kts`
- package declarations under `src/main/java`
- annotations such as `@Controller`, `@RestController`

## 2. Source families

- servlet request getters (`getParameter`, `getHeader`, `getPathInfo`)
- Spring controller method parameters and request objects
- message consumer payload handlers
- configuration values that can be admin-controlled (context dependent)

## 3. Sink families

- Filesystem/resource path APIs
- `Runtime.exec`, `ProcessBuilder`
- URL/HTTP client request APIs
- expression/template evaluators
- JDBC execution methods
- deserialization (`ObjectInputStream`, Jackson polymorphic risks)

## 4. Java-specific strengths

Java signature matching can be precise with:

- package name
- declaring type
- method name
- parameter type list
- argument position

Prefer full signature matching for deterministic qll generation.

## 5. Framework crossover

If Spring Boot detected, load `references/spring.md`.

## 6. Sanitizer patterns

- canonical path containment checks
- command allow-lists and non-shell execution
- URL/domain allow-list and protocol checks
- prepared statements and bind variables
- safe deserialization configuration

## 7. Extraction guidance

Collect candidates from:

- controller/service layers
- utility wrappers around dangerous APIs
- legacy helper classes for command/file operations

Include location metadata to support LLM context prompts.

## 8. Pass-specific notes

- Path traversal: resource loading helpers frequently missed.
- Command injection: wrapper helpers around `ProcessBuilder` need summary edges.
- SSRF: internal HTTP client abstractions can hide sinks.
- SQL injection: ORM raw SQL APIs are key.
- Unsafe deserialization: library configuration APIs matter, not only direct stream reads.

## 9. FP heuristics

- unit/integration test classes -> FP
- DB queries with prepared statements -> FP
- hardcoded trusted URLs for OAuth/OIDC -> likely FP

## 10. Validation checklist

- Signature rendering resolves overloaded methods correctly.
- Labeled sinks map to reachable call sites.
- Query paths include meaningful source-to-sink chain.

## 11. Signature cues for extraction

Source signatures:

- servlet request getters
- Spring request parameter annotations
- message listener payload methods

Sink signatures:

- `Runtime.exec`, `ProcessBuilder.start`
- HTTP client request APIs
- file/resource loading APIs
- raw SQL execution APIs
- deserialization-related constructors/config

## 12. Summary edges

Add summary edges for:

- controller -> service -> repository wrappers
- utility methods that pass tainted values unchanged
- adapter layers around external HTTP/command/sql libraries

## 13. Validation and auth caveats

- Bean validation can reduce false positives but is not universally sanitizing.
- Role checks do not sanitize payload content.

## 14. Prompt context fields

Include:

- fully qualified class and method
- parameter type list
- argument position used as source/sink
- annotation context and snippet

## 15. Review checklist

- overloaded methods disambiguated correctly
- sink labels constrained to dangerous parameter positions
- raw SQL vs prepared statement paths separated clearly
