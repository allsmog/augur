/**
 * Generated sink model for Augur open-webui example.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySinks {
  private predicate hasCalleeName(Call call, string name) {
    exists(Name n | call.getFunc() = n and n.getId() = name)
    or
    exists(Attribute a | call.getFunc() = a and a.getName() = name)
  }

  private predicate sinkCall(DataFlow::Node node, string callee) {
    exists(Call call |
      hasCalleeName(call, callee) and
      node.asExpr() = call
    )
  }

  predicate isSink(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    (
      sinkCall(node, "open")
      or
      sinkCall(node, "FileResponse")
      or
      sinkCall(node, "read_text")
      or
      sinkCall(node, "write_text")
    )
    or
    passKey = "command_injection" and
    (
      sinkCall(node, "run")
      or
      sinkCall(node, "Popen")
      or
      sinkCall(node, "check_output")
      or
      sinkCall(node, "system")
    )
    or
    passKey = "ssrf" and
    (
      sinkCall(node, "request")
      or
      sinkCall(node, "get")
      or
      sinkCall(node, "post")
      or
      sinkCall(node, "urlopen")
    )
    or
    passKey = "code_injection" and
    (
      sinkCall(node, "eval")
      or
      sinkCall(node, "exec")
      or
      sinkCall(node, "compile")
    )
    or
    passKey = "sql_injection" and
    (
      sinkCall(node, "execute")
      or
      sinkCall(node, "executemany")
      or
      sinkCall(node, "text")
    )
    or
    passKey = "unsafe_deserialization" and
    (
      sinkCall(node, "loads")
      or
      sinkCall(node, "load")
    )
  }
}
