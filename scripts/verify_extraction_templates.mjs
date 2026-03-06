import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = process.cwd();

const genericTemplates = [
  {
    path: "assets/extraction/extract_sources.ql.tmpl",
    kind: "source",
    required: [
      "{{QUERY_NAME}}",
      "{{QUERY_DESCRIPTION}}",
      "{{QUERY_ID}}",
      "{{LANGUAGE_IMPORTS}}",
      "{{HELPER_PREDICATES}}",
      "{{SOURCE_CLAUSES}}",
      "{{SELECT_NODE}}",
      "{{SELECT_CALLABLE}}",
      "{{SELECT_FLOW_KIND}}",
      "{{SELECT_RECEIVER}}",
      "{{SELECT_MODULE}}",
      "{{SELECT_ARG_INDEX}}",
      "{{SELECT_LINE}}",
    ],
    replacements: {
      "{{QUERY_NAME}}": "Template Contract Test Source Query",
      "{{QUERY_DESCRIPTION}}": "Rendered source template for contract verification.",
      "{{QUERY_ID}}": "test/template-contract/source",
      "{{LANGUAGE_IMPORTS}}": "import python",
      "{{HELPER_PREDICATES}}": "private predicate sampleHelper() { exists(int i | i = 0) }",
      "{{SOURCE_CLAUSES}}":
        "from Expr node, string callable, string flowKind, string receiverHint, string modulePath, int argIndex, int line\nwhere sampleHelper() and node.toString() = node.toString()",
      "{{SELECT_NODE}}": "node",
      "{{SELECT_CALLABLE}}": "callable",
      "{{SELECT_FLOW_KIND}}": '"flow_kind=" + flowKind',
      "{{SELECT_RECEIVER}}": "receiverHint",
      "{{SELECT_MODULE}}": '"module=" + modulePath',
      "{{SELECT_ARG_INDEX}}": '"arg_index=" + argIndex.toString()',
      "{{SELECT_LINE}}": "line",
    },
    markers: ['"source_candidate"', '"flow_kind=" + flowKind', '"module=" + modulePath'],
  },
  {
    path: "assets/extraction/extract_sinks.ql.tmpl",
    kind: "sink",
    required: [
      "{{QUERY_NAME}}",
      "{{QUERY_DESCRIPTION}}",
      "{{QUERY_ID}}",
      "{{LANGUAGE_IMPORTS}}",
      "{{HELPER_PREDICATES}}",
      "{{SINK_CLAUSES}}",
      "{{SELECT_NODE}}",
      "{{SELECT_CALLABLE}}",
      "{{SELECT_FLOW_KIND}}",
      "{{SELECT_RECEIVER}}",
      "{{SELECT_MODULE}}",
      "{{SELECT_ARG_INDEX}}",
      "{{SELECT_LINE}}",
    ],
    replacements: {
      "{{QUERY_NAME}}": "Template Contract Test Sink Query",
      "{{QUERY_DESCRIPTION}}": "Rendered sink template for contract verification.",
      "{{QUERY_ID}}": "test/template-contract/sink",
      "{{LANGUAGE_IMPORTS}}": "import python",
      "{{HELPER_PREDICATES}}": "private predicate sampleHelper() { exists(int i | i = 0) }",
      "{{SINK_CLAUSES}}":
        "from Expr node, string callable, string flowKind, string receiverHint, string modulePath, int argIndex, int line\nwhere sampleHelper() and node.toString() = node.toString()",
      "{{SELECT_NODE}}": "node",
      "{{SELECT_CALLABLE}}": "callable",
      "{{SELECT_FLOW_KIND}}": '"flow_kind=" + flowKind',
      "{{SELECT_RECEIVER}}": "receiverHint",
      "{{SELECT_MODULE}}": '"module=" + modulePath',
      "{{SELECT_ARG_INDEX}}": '"arg_index=" + argIndex.toString()',
      "{{SELECT_LINE}}": "line",
    },
    markers: ['"sink_candidate"', '"flow_kind=" + flowKind', '"module=" + modulePath'],
  },
];

const starterTemplates = [
  {
    path: "assets/extraction/python_sources.ql.tmpl",
    kind: "source",
  },
  {
    path: "assets/extraction/go_sources.ql.tmpl",
    kind: "source",
  },
  {
    path: "assets/extraction/java_sources.ql.tmpl",
    kind: "source",
  },
  {
    path: "assets/extraction/javascript_sources.ql.tmpl",
    kind: "source",
  },
  {
    path: "assets/extraction/csharp_sources.ql.tmpl",
    kind: "source",
  },
  {
    path: "assets/extraction/python_sinks.ql.tmpl",
    kind: "sink",
  },
  {
    path: "assets/extraction/go_sinks.ql.tmpl",
    kind: "sink",
  },
  {
    path: "assets/extraction/java_sinks.ql.tmpl",
    kind: "sink",
  },
  {
    path: "assets/extraction/javascript_sinks.ql.tmpl",
    kind: "sink",
  },
  {
    path: "assets/extraction/csharp_sinks.ql.tmpl",
    kind: "sink",
  },
];

function read(path) {
  return readFileSync(join(root, path), "utf8");
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function render(template, replacements) {
  let rendered = template;
  for (const [placeholder, value] of Object.entries(replacements)) {
    rendered = rendered.replaceAll(placeholder, value);
  }
  return rendered;
}

for (const template of genericTemplates) {
  const body = read(template.path);
  for (const placeholder of template.required) {
    assert(body.includes(placeholder), `${template.path} is missing ${placeholder}`);
  }

  const rendered = render(body, template.replacements);
  assert(!rendered.includes("{{"), `${template.path} still contains unresolved placeholders after rendering`);
  assert(rendered.includes("select"), `${template.path} does not render a select clause`);
  for (const marker of template.markers) {
    assert(rendered.includes(marker), `${template.path} did not render expected marker ${marker}`);
  }
}

for (const template of starterTemplates) {
  const body = read(template.path);
  const predicateToken =
    template.kind === "source" ? "{{SOURCE_HANDLER_PREDICATE}}" : "{{SINK_CALL_PREDICATE}}";
  const bindingsToken =
    template.kind === "source" ? "{{SOURCE_NODE_BINDINGS}}" : "{{SINK_NODE_BINDINGS}}";
  const whereToken = template.kind === "source" ? "{{SOURCE_WHERE}}" : "{{SINK_WHERE}}";
  const selectToken = template.kind === "source" ? "{{SOURCE_SELECT}}" : "{{SINK_SELECT}}";

  assert(body.includes(predicateToken), `${template.path} is missing ${predicateToken}`);
  assert(body.includes(bindingsToken), `${template.path} is missing ${bindingsToken}`);
  assert(body.includes(whereToken), `${template.path} is missing ${whereToken}`);
  assert(body.includes(selectToken), `${template.path} is missing ${selectToken}`);

  const rendered = render(body, {
    "{{QUERY_NAME}}": `Starter Contract Test ${template.kind}`,
    "{{QUERY_ID}}": `test/starter-contract/${template.kind}`,
    [predicateToken]: "private predicate samplePredicate() { exists(int i | i = 0) }",
    [bindingsToken]:
      "Expr node, string callable, string flowKind, string receiverHint, string modulePath, int argIndex, int line",
    [whereToken]: "samplePredicate() and node.toString() = node.toString()",
    [selectToken]:
      'node,\n  "' +
      `${template.kind}_candidate` +
      '",\n  callable,\n  "flow_kind=" + flowKind,\n  receiverHint,\n  "module=" + modulePath,\n  "arg_index=" + argIndex.toString(),\n  line',
  });

  assert(!rendered.includes("{{"), `${template.path} still contains unresolved placeholders after rendering`);
  assert(
    rendered.includes(`"${template.kind}_candidate"`),
    `${template.path} did not render the expected candidate kind`,
  );
  assert(rendered.includes('from Expr node'), `${template.path} did not render the expected from clause`);
  assert(rendered.includes('where samplePredicate()'), `${template.path} did not render the expected where clause`);
  assert(rendered.includes('"flow_kind=" + flowKind'), `${template.path} lost flow kind rendering`);
  assert(rendered.includes("receiverHint"), `${template.path} lost receiver rendering`);
  assert(rendered.includes('"module=" + modulePath'), `${template.path} lost module rendering`);
  assert(rendered.includes('"arg_index=" + argIndex.toString()'), `${template.path} lost arg index rendering`);
  assert(rendered.includes("\n  line"), `${template.path} lost line rendering`);
}

for (const [path, legacyMarker] of [
  ["assets/extraction/python_sources.ql.tmpl", "private predicate isRouteDecoratorExpr"],
  ["assets/extraction/python_sinks.ql.tmpl", "private predicate sinkName"],
]) {
  const body = read(path);
  assert(!body.includes(legacyMarker), `${path} still contains legacy hardcoded extraction logic`);
}

console.log("Verified extraction template contracts for generic and starter templates.");
