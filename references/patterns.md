# CodeQL Rosetta Stone (Cross-Language)

Use this file to map common query concepts across Python, Go, Java, JavaScript/TypeScript, and C#.

Load this file first, then load the language-specific reference.

## 1. Import model and module roots

| Concept | Python | Go | Java | JavaScript/TypeScript | C# |
| --- | --- | --- | --- | --- | --- |
| Base import | `import python` | `import go` | `import java` | `import javascript` | `import csharp` |
| Data flow module | `semmle.python.dataflow.new.*` | `semmle.go.dataflow.new.*` | `semmle.code.java.dataflow.*` | `semmle.javascript.dataflow.*` | `semmle.code.csharp.dataflow.*` |
| Taint tracking | `TaintTracking` | `TaintTracking` | `TaintTracking` | `TaintTracking` | `TaintTracking` |

Notes:

- New dataflow libraries vary by language and CodeQL version.
- Keep imports minimal and consistent with generated query templates.

## 2. Calls and callable targets

| Concept | Python | Go | Java | JavaScript/TypeScript | C# |
| --- | --- | --- | --- | --- | --- |
| Call expression class | `CallNode` / call expr classes | call expression node types | `MethodCall` / call-related expressions | `CallExpr` / invoke node types | invocation expression types |
| Get callee | callable expression from call node | target function/method symbol | target method resolution | callee expression / resolved function | target method symbol |
| Arg access | argument index APIs | argument index APIs | `getArgument(i)` style | `getArgument(i)` style | argument APIs |

Pattern:

1. Resolve call-site expression.
2. Resolve callable symbol (name + package/module + receiver type).
3. Compare against labeled signatures.

## 3. Member and attribute access

| Concept | Python | Go | Java | JavaScript/TypeScript | C# |
| --- | --- | --- | --- | --- | --- |
| Field/member read | attribute expr | selector expr | field access | property/member access | member access expr |
| Method call with receiver | attribute + call | selector call | virtual/static method call | member call | instance/static invocation |

Use receiver type constraints to reduce ambiguity for overloaded or common names.

## 4. Function/method definitions

| Concept | Python | Go | Java | JavaScript/TypeScript | C# |
| --- | --- | --- | --- | --- | --- |
| Function definition | function class | function declaration | method/constructor declarations | function/method declarations | method/constructor declarations |
| Parameter access | parameter node APIs | parameter node APIs | formal parameter APIs | parameter node APIs | parameter APIs |
| Return expression | return stmt expr | return stmt expr | return statement expr | return statement expr | return statement expr |

Use definition-side analysis for internal API source mining.

## 5. Type system matching

| Concept | Python | Go | Java | JavaScript/TypeScript | C# |
| --- | --- | --- | --- | --- | --- |
| Static type precision | often weak/dynamic | strong static types | strong static types | mixed (JS weak, TS stronger) | strong static types |
| Receiver constraints | inferred/nominal heuristics | concrete receiver type | declaring type + inheritance | prototype/type model | declaring type + inheritance |

Guideline:

- Prefer fully-qualified signature matching where possible.
- Fall back to name + module/package + argument count when dynamic resolution is weak.

## 6. DataFlow node mapping

| Label role | Preferred node mapping |
| --- | --- |
| Source | function params, HTTP request accessors, env/config reads, deserialization input |
| Sink | filesystem writes/opens, command execution, HTTP fetchers, template evaluators, SQL execution, deserializers |
| Sanitizer | normalization, canonicalization, path guards, query parameterization, allow-list checks |
| Summary step | wrapper/helper functions that transfer taint semantically |

Map each label entry to a concrete `DataFlow::Node` predicate.

## 7. Query configuration skeleton

Use a generated configuration per pass:

1. `isSource(node)` delegates to `MySources` with pass key
2. `isSink(node)` delegates to `MySinks` with pass key
3. `isBarrier(node)` delegates to `MySanitizers` (must exist even if empty)
4. Optional `isAdditionalFlowStep(a,b)` delegates to `MySummaries`

Then query with `hasFlowPath(source,sink)` and emit path-problem alerts.

## 8. Common source families by framework

- HTTP request path/query/body/header/cookie fields
- RPC payload deserialization outputs
- Message queue payloads
- CLI args and environment variables
- Database content reused in dynamic execution contexts

## 9. Common sink families by CWE pass

Pass 1 path traversal:

- file open/read/write APIs with user-controlled path
- resource loader methods taking path strings

Pass 2 command injection:

- shell/process execution calls
- argument array invocations when args include untrusted data

Pass 3 SSRF:

- HTTP clients requesting attacker-controlled URL
- webhook forwarding to dynamic targets

Pass 4 code injection:

- `eval`-like APIs
- template expression engines in executable mode

Pass 5 SQL injection:

- raw SQL execute methods with string concatenation/interpolation

Pass 6 unsafe deserialization:

- binary/json/xml deserialization APIs without type restrictions

## 10. Sanitizer patterns to look for

- Canonical path checks with base directory containment
- Allow-list on protocols/domains for URL sinks
- Strict command argument construction without shell parsing
- SQL bind parameters / prepared statements
- Deserializer safe modes (type allow-list, disabled polymorphism)

## 11. Extraction query design

Extract broad candidates first, filter later.

Recommended fields:

- package/module
- class/receiver
- callable name
- arg index
- location
- usage snippet

Keep extraction logic language-specific, but preserve output schema across languages.

## 12. Pitfalls

- Overly generic source labels explode path counts.
- Overly generic sink labels produce low-value findings.
- Missing framework wrappers reduce recall.
- Missing summary edges under-report real paths.
- Parallel CodeQL runs on one DB can fail with lock/contention errors.

## 13. Portability checklist for new language support

1. Add `references/<language>.md` with AST/dataflow primitives.
2. Implement extraction queries for source/sink candidates.
3. Implement signature-to-node mapping renderer for generated `.qll`.
4. Reuse `labels_schema.json` unchanged.
5. Reuse `taint_query.ql.tmpl` with language-specific imports/hooks.

## 14. Minimum quality bar

Before advancing to Phase 2:

- Candidate extraction has non-trivial coverage (sources and sinks both non-empty unless documented).
- Labels are schema-valid.
- Duplicate signature entries are removed.
- Pass-specific libraries compile in query parsing phase.
