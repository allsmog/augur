# Go CodeQL Patterns

Use this reference when detected language is Go.

## 1. Detection

Key indicators:

- `go.mod`
- imports with module paths
- packages under `cmd/`, `internal/`, `pkg/`

## 2. Core sink families

- File operations: `os.OpenFile`, `os.ReadFile`, `ioutil` legacy APIs
- Command execution: `os/exec` (`Command`, `CommandContext`)
- HTTP client calls: `net/http` and third-party clients
- SQL execution: `database/sql` raw query methods
- Deserialization: `encoding/gob`, `yaml`, `json` custom unmarshal hooks

## 3. Common source families

- HTTP request path/query/body/header values
- CLI/environment input
- message queue payloads
- deserialized structs from untrusted channels

## 4. Framework crossover

If Gin or Echo detected, load framework reference:

- `references/gin.md`
- `references/echo.md`

## 5. Sanitizer patterns

- strict path canonicalization and base-dir checks
- command argument allow-list
- URL scheme/host allow-list
- SQL bind parameters (`?`, `$1`, etc)

## 6. Extraction tips

Capture:

- package
- receiver type (for methods)
- function name
- argument index
- call location

Go methods on struct receivers should keep receiver type to avoid name collisions.

## 7. Pass-specific caveats

- Path traversal: watch archive extraction and file-serving helpers.
- Command injection: shell wrappers around `sh -c` are high risk.
- SSRF: webhook forwarding and proxy endpoints are frequent sinks.
- SQL injection: string-built queries into `Exec`, `Query`, `QueryRow`.

## 8. FP heuristics

- test files and generated mocks -> FP
- migration-only SQL builders -> FP
- safe parameterized DB calls -> FP

## 9. Validation checklist

- Extraction covers both handler boundary and sink APIs.
- Labels include receiver-qualified signatures.
- Query output includes meaningful path traces.

## 10. Signature cues for extraction

Source signatures:

- HTTP framework context getters
- `os.Getenv`, CLI arg parsing helpers
- request decoding helpers (`json.NewDecoder(...).Decode(...)`)

Sink signatures:

- filesystem APIs (`os.OpenFile`, `os.ReadFile`, `os.WriteFile`)
- command APIs (`exec.Command`, `exec.CommandContext`)
- HTTP outbound calls (`http.NewRequest`, client `Do`)
- SQL methods (`Exec`, `Query`, `QueryRow`)
- deserialization (`gob`, unsafe YAML decode)

## 11. Wrapper modeling

Add summary edges for:

- handler -> service -> utility -> sink
- DTO mapper helpers passing tainted fields
- query builder helpers constructing SQL strings

## 12. Validation caveats

- struct validation tags constrain shape, not always exploitability
- auth middleware constrains actor, not taint source trust

## 13. Prompt context fields

Include in labels prompt:

- package path
- receiver type
- function signature
- argument index and call-site snippet

## 14. Review checklist

- pass coverage across file/command/http/sql/deserialize sink families
- sanitizer labels correspond to explicit neutralization patterns
- high-volume generic calls are bounded by package/receiver filters
