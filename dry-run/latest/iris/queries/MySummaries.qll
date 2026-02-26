/**
 * Generated summary/additional-flow model for Augur open-webui example.
 */

import python
import semmle.python.dataflow.new.DataFlow

module MySummaries {
  private predicate hasCalleeName(Call call, string name) {
    exists(Name n | call.getFunc() = n and n.getId() = name)
    or
    exists(Attribute a | call.getFunc() = a and a.getName() = name)
  }

  predicate isAdditionalTaintStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo, string passKey) {
    (
      passKey = "path_traversal"
      or passKey = "command_injection"
      or passKey = "ssrf"
      or passKey = "code_injection"
      or passKey = "sql_injection"
      or passKey = "unsafe_deserialization"
    )
    and
    exists(Call call |
      hasCalleeName(call, "str") and
      nodeFrom.asExpr() = call.getArg(0) and
      nodeTo.asExpr() = call
    )
  }
}
