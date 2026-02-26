/**
 * Generated source model for Augur open-webui example.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySources {
  private predicate hasCalleeName(Call call, string name) {
    exists(Name n | call.getFunc() = n and n.getId() = name)
    or
    exists(Attribute a | call.getFunc() = a and a.getName() = name)
  }

  private predicate callResult(DataFlow::Node node, string callee) {
    exists(Call call |
      hasCalleeName(call, callee) and
      node.asExpr() = call
    )
  }

  private predicate isFastApiBoundary(DataFlow::Node node) {
    callResult(node, "Query")
    or
    callResult(node, "Path")
    or
    callResult(node, "Body")
    or
    callResult(node, "Header")
    or
    callResult(node, "Cookie")
    or
    callResult(node, "json")
    or
    callResult(node, "get")
  }

  predicate isSource(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and isFastApiBoundary(node)
    or
    passKey = "command_injection" and isFastApiBoundary(node)
    or
    passKey = "ssrf" and isFastApiBoundary(node)
    or
    passKey = "code_injection" and isFastApiBoundary(node)
    or
    passKey = "sql_injection" and isFastApiBoundary(node)
    or
    passKey = "unsafe_deserialization" and isFastApiBoundary(node)
  }
}
