# Extraction Templates

Use these templates in Step 2 to generate source and sink extraction queries.

Files:

- `extract_sources.ql.tmpl` and `extract_sinks.ql.tmpl`: generic skeletons
- `python_sources.ql.tmpl` and `python_sinks.ql.tmpl`: concrete Python starters
- `go_*.ql.tmpl`, `java_*.ql.tmpl`, `javascript_*.ql.tmpl`, `csharp_*.ql.tmpl`: language starters

Minimum output columns expected by Augur extraction summary and labeling:

1. candidate kind (`source_candidate` or `sink_candidate`)
2. callable name
3. flow kind (`param`, `argument`, `return`, `receiver`, `field`)
4. receiver/module hint
5. arg index (or `-1` when not applicable)
6. source location line

Use language/framework references to fill language-specific placeholders.
