/**
 * @name Augur Pass 3 - SSRF
 * @description Detect tainted URL-like input reaching outbound request sinks.
 * @kind path-problem
 * @problem.severity error
 * @precision medium
 * @id py/augur/pass3-ssrf
 * @tags security
 *       external/cwe/cwe-918
 *       external/cwe/cwe-099
 *       external/cwe/cwe-610
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import MySources
import MySinks
import MySanitizers
import MySummaries

module Pass3Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    MySources::isSource(source, "ssrf")
  }

  predicate isSink(DataFlow::Node sink) {
    MySinks::isSink(sink, "ssrf")
  }

  predicate isBarrier(DataFlow::Node node) {
    MySanitizers::isBarrier(node, "ssrf")
    or
    none()
  }

  predicate isAdditionalFlowStep(DataFlow::Node nodeFrom, DataFlow::Node nodeTo) {
    MySummaries::isAdditionalTaintStep(nodeFrom, nodeTo, "ssrf")
  }
}

module Pass3Flow = TaintTracking::Global<Pass3Config>;
import Pass3Flow::PathGraph

from Pass3Flow::PathNode source, Pass3Flow::PathNode sink
where Pass3Flow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential SSRF flow from $@ to $@.",
  source.getNode(), "source",
  sink.getNode(), "sink"
