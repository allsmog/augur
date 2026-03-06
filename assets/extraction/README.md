# Extraction Templates

Use these templates in Step 2 to generate source and sink extraction queries.

Files:

- `extract_sources.ql.tmpl` and `extract_sinks.ql.tmpl`: generic skeletons
- `python_*.ql.tmpl`, `go_*.ql.tmpl`, `java_*.ql.tmpl`, `javascript_*.ql.tmpl`, `csharp_*.ql.tmpl`: language starter stubs

Minimum output columns expected by Augur extraction summary and labeling:

1. candidate kind (`source_candidate` or `sink_candidate`)
2. callable name
3. flow kind (`param`, `argument`, `return`, `receiver`, `field`)
4. receiver/module hint
5. arg index (or `-1` when not applicable)
6. source location line

All language starter templates use the same placeholder contract:

- sources: `{{SOURCE_HANDLER_PREDICATE}}`, `{{SOURCE_NODE_BINDINGS}}`, `{{SOURCE_WHERE}}`, `{{SOURCE_SELECT}}`
- sinks: `{{SINK_CALL_PREDICATE}}`, `{{SINK_NODE_BINDINGS}}`, `{{SINK_WHERE}}`, `{{SINK_SELECT}}`

Synthesize these placeholders from observed repo signals first, then augment with matching
language/framework references. If no justified candidate family exists, emit a valid no-match
fragment instead of a speculative baseline.
