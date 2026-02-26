# Spring Boot Source/Sink Signatures

Use when Java + Spring Boot is detected.

## 1. Detection heuristics

- annotations: `@RestController`, `@Controller`, `@RequestMapping`
- Spring MVC method signatures and request annotations

## 2. Source patterns

- `@RequestParam`, `@PathVariable`, `@RequestBody`
- servlet request getters within controllers/filters
- headers/cookies from request objects

## 3. Sink patterns

- filesystem/resource operations with request-derived input
- `Runtime.exec` / `ProcessBuilder`
- RestTemplate/WebClient with dynamic URL
- expression/template evaluation APIs
- JDBC raw SQL execution
- unsafe deserialization config/usage

## 4. Sanitizer patterns

- explicit validation annotations plus downstream enforcement
- allow-lists for URL/domain/commands
- prepared statements and bind parameters

## 5. FP heuristics

- test classes and mock MVC fixtures -> FP
- migration utilities -> FP
- known prepared statement calls -> FP for pass 5

## 6. Signature cues for extraction

Source candidates:

- `@RequestParam`, `@PathVariable`, `@RequestBody`
- `HttpServletRequest.getParameter/getHeader/getPathInfo`
- deserialized request DTO fields

Sink candidates:

- `Runtime.getRuntime().exec(...)`
- `new ProcessBuilder(...).start()`
- `RestTemplate.exchange/getForObject/postForEntity`
- `WebClient` request builders with dynamic URI
- `JdbcTemplate.query/execute` with raw SQL
- expression engine evaluators and unsafe deserializers

## 7. Layering and summary edges

Spring code often uses controller-service-repository layering.

Add summary edges across:

- controller params -> service DTO -> sink invocation
- helper methods normalizing/formatting values
- custom repository wrappers for SQL execution

## 8. Validation and auth caveats

- Bean validation annotations limit shape but may not neutralize exploit strings.
- security annotations constrain caller but not taint trust.

## 9. Pass notes

Path Traversal:

- file/resource loader endpoints

Command Injection:

- command wrappers in admin/ops features

SSRF:

- remote fetch clients with user-supplied URL

Code Injection:

- expression parsers/scripting modules

SQL Injection:

- raw SQL in `JdbcTemplate`/entity manager native queries

Unsafe Deserialization:

- Jackson polymorphism and legacy deserializer settings

## 10. FP reductions

- test slices and mock MVC flows -> FP
- migration scripts -> FP
- prepared statements/bind params -> FP for SQL injection

## 11. Labeling context fields

Include:

- annotation context
- declaring type and package
- argument role (param/body/header)
- sink API and parameter position

## 12. CodeQL predicate sketch

```ql
import java

predicate isSpringControllerParamSource(DataFlow::Node n) {
  exists(Parameter p |
    p.getAnAnnotation().getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") and
    n.asParameter() = p
  )
}
```
