# JavaScript/TypeScript CodeQL Patterns

Use this reference when detected language is JavaScript or TypeScript.

## 1. Detection

Indicators:

- `package.json`
- `tsconfig.json` (TypeScript)
- common frameworks/libraries (`express`, `koa`, `fastify`, etc.)

## 2. Source families

- HTTP request params/query/body/headers/cookies
- websocket and RPC payloads
- CLI args and env vars
- data returned from untrusted storage/queues

## 3. Sink families

- path/file APIs (`fs`, path joins into file operations)
- command execution (`child_process`)
- outbound network requests (`fetch`, axios, request libs)
- dynamic evaluation (`eval`, `Function`, vm APIs)
- SQL execution (`query`, raw SQL methods)
- deserialization helpers (unsafe object construction patterns)

## 4. Framework crossover

If Express is detected, load `references/express.md`.

## 5. Type model caveats

JS is dynamic; TS adds typing but runtime remains dynamic.

Mitigation:

- constrain by import/module
- constrain by member names and argument positions
- use surrounding call chain context

## 6. Sanitizer patterns

- path normalization + root confinement
- command argument array usage with strict validation
- URL allow-lists
- parameterized SQL APIs

## 7. Extraction guidance

Collect both:

- direct dangerous API calls
- wrapper helpers in utility modules

Record:

- module path
- function/method name
- arg index
- call snippet
- location

## 8. Pass-specific notes

- Path traversal in file-serving endpoints is common.
- SSRF appears in webhook/proxy features.
- Code injection often appears in plugin/template systems.
- SQL injection depends on ORM raw query escape hatches.

## 9. FP heuristics

- test/spec files -> FP
- migration/seeding scripts -> FP for most passes
- known prepared query methods -> FP

## 10. Validation checklist

- Candidate extraction includes framework handlers.
- Labels separate string formatting helpers from true sinks.
- Queries produce path traces with actionable call chain context.

## 11. Signature cues for extraction

Source signatures:

- Express/Fastify/Koa request payload accessors
- websocket event payloads
- CLI/env utilities

Sink signatures:

- fs path operations
- child process execution APIs
- outbound HTTP request methods
- eval/vm APIs
- raw SQL methods

## 12. Wrapper modeling

Add summary edges for:

- route -> controller -> service wrappers
- utility functions that forward tainted values
- custom query builder helpers

## 13. Runtime caveats

- transpiled TS may obscure source locations; keep original source-map context if available.
- dynamic property access can reduce precision; use module + call-shape constraints.

## 14. Prompt context fields

Include:

- module path
- function or method signature
- argument index and sink API variant
- middleware chain notes

## 15. Review checklist

- sink labels separate `execFile/spawn` from shell-unsafe patterns
- SQL labels capture raw query paths and exclude safe parameterized variants
- SSRF labels distinguish fixed trusted endpoints from user-controlled URLs
