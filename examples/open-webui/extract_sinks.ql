/**
 * @name Augur extraction - sink candidates (Python/FastAPI)
 * @description Extract sink-like API usages with arg index and receiver context.
 * @kind problem
 * @id py/augur/extract-sinks
 * @problem.severity recommendation
 */

import python

private predicate callContext(
  Call call, string callee, string receiverExpr, string modulePath, int line
) {
  (
    exists(Name n |
      call.getFunc() = n and
      callee = n.getId() and
      receiverExpr = ""
    )
    or
    exists(Attribute a |
      call.getFunc() = a and
      callee = a.getName() and
      receiverExpr = a.getObject().toString()
    )
  )
  and
  modulePath = call.getLocation().getFile().getRelativePath() and
  line = call.getLocation().getStartLine()
}

private predicate candidateSinkName(string name) {
  name = "open"
  or
  name = "run"
  or
  name = "Popen"
  or
  name = "request"
  or
  name = "get"
  or
  name = "post"
  or
  name = "eval"
  or
  name = "exec"
  or
  name = "execute"
  or
  name = "loads"
  or
  name = "load"
}

private int preferredSinkArgIndex(string callee) {
  callee = "open" and result = 0
  or
  callee = "run" and result = 0
  or
  callee = "Popen" and result = 0
  or
  callee = "request" and result = 0
  or
  callee = "get" and result = 0
  or
  callee = "post" and result = 0
  or
  callee = "eval" and result = 0
  or
  callee = "exec" and result = 0
  or
  callee = "execute" and result = 0
  or
  callee = "loads" and result = 0
  or
  callee = "load" and result = 0
}

from
  Call call,
  string callee,
  string receiverExpr,
  string modulePath,
  int line,
  int argIndex,
  Expr arg
where
  callContext(call, callee, receiverExpr, modulePath, line) and
  candidateSinkName(callee) and
  argIndex = preferredSinkArgIndex(callee) and
  arg = call.getArg(argIndex)
select
  arg,
  "sink_candidate",
  callee,
  "flow_kind=argument",
  "receiver=" + receiverExpr + ";receiver_type_hint=" + receiverExpr,
  "module=" + modulePath,
  "arg_index=" + argIndex.toString(),
  line
