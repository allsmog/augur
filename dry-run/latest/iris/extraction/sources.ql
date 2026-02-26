/**
 * @name Augur extraction - source candidates (Python)
 * @description Python source extraction template.
 * @kind problem
 * @id py/augur/extract-sources
 * @problem.severity recommendation
 */

import python

private predicate isRouteDecoratorExpr(Expr deco) {
  deco.toString().regexpMatch(".*\\.(get|post|put|patch|delete|route)\\(.*")
  or
  deco.toString().regexpMatch(".*router\\.(get|post|put|patch|delete)\\(.*")
}

private predicate isRouteHandler(Function f) {
  exists(Expr deco | deco = f.getADecorator() and isRouteDecoratorExpr(deco))
}

private predicate sourceFactoryName(string name) {
  name = "Query"
  or name = "Path"
  or name = "Body"
  or name = "Header"
  or name = "Cookie"
  or name = "json"
  or name = "get"
}

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

private predicate sourceCandidate(
  Expr node,
  string callable,
  string flowKind,
  string receiverHint,
  string modulePath,
  int argIndex,
  int line
) {
  exists(Function f, Parameter p |
    isRouteHandler(f) and
    p = f.getArg(_) and
    not p.isSelf() and
    node = p.asName() and
    callable = f.getName() and
    flowKind = "param" and
    receiverHint = "handler=" + f.getName() and
    modulePath = p.getLocation().getFile().getRelativePath() and
    argIndex = p.getPosition() and
    line = p.getLocation().getStartLine()
  )
  or
  exists(Call call, string callee, string receiverExpr |
    callContext(call, callee, receiverExpr, modulePath, line) and
    sourceFactoryName(callee) and
    node = call and
    callable = callee and
    flowKind = "return" and
    receiverHint = "receiver=" + receiverExpr and
    argIndex = -1
  )
}

from Expr node, string callable, string flowKind, string receiverHint, string modulePath, int argIndex, int line
where sourceCandidate(node, callable, flowKind, receiverHint, modulePath, argIndex, line)
select
  node,
  "source_candidate",
  callable,
  "flow_kind=" + flowKind,
  receiverHint,
  "module=" + modulePath,
  "arg_index=" + argIndex.toString(),
  line
