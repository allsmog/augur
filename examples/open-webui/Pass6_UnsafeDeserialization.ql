/**
 * @name Augur Pass 6 - Unsafe Deserialization
 * @description Detect tainted content reaching unsafe deserialization sinks.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id py/augur/pass6-unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks
import MySanitizers
import MySummaries

module Pass6Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "unsafe_deserialization")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "unsafe_deserialization")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "unsafe_deserialization")
    or
    none()
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "unsafe_deserialization")
  }
}

module Pass6Flow = TaintTracking::Global<Pass6Config>;
import Pass6Flow::PathGraph

from Pass6Flow::PathNode source, Pass6Flow::PathNode sink
where Pass6Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential unsafe deserialization flow from $@ to $@.",
  source.getNode(), "source",
  sink.getNode(), "sink"
