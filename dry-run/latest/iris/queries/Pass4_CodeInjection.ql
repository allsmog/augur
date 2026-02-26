/**
 * @name Augur Pass 4 - Code Injection
 * @description Detect tainted data reaching dynamic code execution sinks.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id py/augur/pass4-code-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks
import MySanitizers
import MySummaries

module Pass4Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "code_injection")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "code_injection")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "code_injection")
    or
    none()
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "code_injection")
  }
}

module Pass4Flow = TaintTracking::Global<Pass4Config>;
import Pass4Flow::PathGraph

from Pass4Flow::PathNode source, Pass4Flow::PathNode sink
where Pass4Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential code injection flow from $@ to $@.",
  source.getNode(), "source",
  sink.getNode(), "sink"
