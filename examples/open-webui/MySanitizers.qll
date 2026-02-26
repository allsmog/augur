/**
 * Generated sanitizer model for Augur open-webui example.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySanitizers {
  private predicate hasCalleeName(Call call, string name) {
    exists(Name n | call.getFunc() = n and n.getId() = name)
    or
    exists(Attribute a | call.getFunc() = a and a.getName() = name)
  }

  private predicate callIs(DataFlow::Node node, string callee) {
    exists(Call call |
      hasCalleeName(call, callee) and
      node.asExpr() = call
    )
  }

  predicate isBarrier(DataFlow::Node node, string passKey) {
    passKey = "path_traversal" and
    (
      callIs(node, "basename")
      or
      callIs(node, "normpath")
      or
      callIs(node, "realpath")
      or
      callIs(node, "safe_join")
    )
    or
    passKey = "ssrf" and
    (
      callIs(node, "validate_url")
      or
      callIs(node, "is_safe_url")
      or
      callIs(node, "allowlisted_url")
    )
    or
    passKey = "sql_injection" and
    (
      callIs(node, "bindparam")
      or
      callIs(node, "prepare")
      or
      callIs(node, "parameterized")
    )
    or
    passKey = "command_injection" and
    (
      callIs(node, "validate_command")
      or
      callIs(node, "allowed_command")
    )
    or
    passKey = "code_injection" and
    callIs(node, "safe_eval")
    or
    passKey = "unsafe_deserialization" and
    (
      callIs(node, "safe_load")
      or
      callIs(node, "strict_load")
    )
  }
}
