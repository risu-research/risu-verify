from __future__ import annotations

import ast
from typing import Any, Dict, List, Sequence


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute):
        base=_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):
        base=_name(node.value)
        if base:
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value,(str,int)):
                return f"{base}[{node.slice.value!r}]"
            return f"{base}[]"
    return None


def _labels(node: ast.AST | None) -> List[str]:
    if node is None: return []
    out=set()
    for n in ast.walk(node):
        x=_name(n)
        if x: out.add(x)
    return sorted(out)


def _span(node: ast.AST) -> Dict[str,int]:
    return {
        "start_line":max(1,getattr(node,"lineno",1)),
        "start_col":max(0,getattr(node,"col_offset",0)),
        "end_line":max(1,getattr(node,"end_lineno",getattr(node,"lineno",1))),
        "end_col":max(0,getattr(node,"end_col_offset",getattr(node,"col_offset",0)+1)),
    }


class Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope="<module>"
        self.facts: List[Dict[str,Any]]=[]

    def emit(self,node:ast.AST,kind:str,**attrs:Any) -> None:
        self.facts.append({"kind":kind,"scope":self.scope,"span":_span(node),**attrs})

    def visit_FunctionDef(self,node:ast.FunctionDef) -> Any:
        old=self.scope
        params=[a.arg for a in list(node.args.posonlyargs)+list(node.args.args)+list(node.args.kwonlyargs)]
        if node.args.vararg: params.append("*"+node.args.vararg.arg)
        if node.args.kwarg: params.append("**"+node.args.kwarg.arg)
        self.emit(node,"FUNCTION",name=node.name,params=params)
        self.scope=node.name
        for stmt in node.body: self.visit(stmt)
        self.scope=old
    visit_AsyncFunctionDef=visit_FunctionDef

    def visit_Assign(self,node:ast.Assign) -> Any:
        lhs=sorted({x for t in node.targets for x in _labels(t)})
        rhs=_labels(node.value)
        self.emit(node,"ASSIGN",lhs=lhs,rhs=rhs,value_kind=type(node.value).__name__)
        if isinstance(node.value,ast.Call): self._emit_call(node.value,result_labels=lhs)
        self._emit_container_binds(node.value)
        for t in node.targets: self.visit(t)
        if not isinstance(node.value,ast.Call): self.visit(node.value)

    def visit_AnnAssign(self,node:ast.AnnAssign) -> Any:
        lhs=_labels(node.target); rhs=_labels(node.value)
        self.emit(node,"ASSIGN",lhs=lhs,rhs=rhs,value_kind=type(node.value).__name__ if node.value else "None")
        if isinstance(node.value,ast.Call): self._emit_call(node.value,result_labels=lhs)
        self._emit_container_binds(node.value)
        self.visit(node.target)
        if node.value is not None and not isinstance(node.value,ast.Call): self.visit(node.value)

    def visit_NamedExpr(self,node:ast.NamedExpr) -> Any:
        self.emit(node,"ASSIGN",lhs=_labels(node.target),rhs=_labels(node.value),value_kind=type(node.value).__name__)
        self.generic_visit(node)

    def _emit_container_binds(self,node:ast.AST | None) -> None:
        if isinstance(node,ast.Dict):
            for k,v in zip(node.keys,node.values):
                if isinstance(k,ast.Constant) and isinstance(k.value,str):
                    self.emit(v,"FIELD_BIND",container="dict",field=k.value,rhs=_labels(v))
        elif isinstance(node,ast.Call):
            callee=_name(node.func) or "<dynamic>"
            for kw in node.keywords:
                if kw.arg: self.emit(kw.value,"FIELD_BIND",container=callee,field=kw.arg,rhs=_labels(kw.value))

    def _emit_call(self,node:ast.Call,result_labels:Sequence[str]=()) -> None:
        callee=_name(node.func) or "<dynamic>"
        args=[_labels(a) for a in node.args]
        kwargs={kw.arg:_labels(kw.value) for kw in node.keywords if kw.arg}
        self.emit(node,"CALL",callee=callee,args=args,kwargs=kwargs,result_labels=list(result_labels))
        self._emit_container_binds(node)

    def visit_Call(self,node:ast.Call) -> Any:
        self._emit_call(node)
        self.generic_visit(node)

    def visit_Compare(self,node:ast.Compare) -> Any:
        operands=[_labels(node.left)]+[_labels(x) for x in node.comparators]
        operators=[type(x).__name__ for x in node.ops]
        self.emit(node,"COMPARE",operands=operands,operators=operators)
        self.generic_visit(node)

    def visit_If(self,node:ast.If) -> Any:
        self.emit(node.test,"IF_GUARD",condition=_labels(node.test),body_span=_span(node))
        self.generic_visit(node)

    def visit_Return(self,node:ast.Return) -> Any:
        self.emit(node,"RETURN",values=_labels(node.value))
        # v0.2 remediation R4: recurse structurally through the returned expression.
        # visit_Call emits the outer call exactly once and generic_visit then emits nested calls.
        if node.value is not None:
            self.visit(node.value)


def extract(source:str) -> Dict[str,Any]:
    try:
        tree=ast.parse(source)
    except SyntaxError as exc:
        return {"status":"MATERIAL_PARSE_FAILURE","parser":"python.stdlib.ast.v0.2",
                "error":f"{exc.__class__.__name__}:{exc.msg}","facts":[]}
    v=Visitor(); v.visit(tree)
    v.facts.sort(key=lambda f:(f["span"]["start_line"],f["span"]["start_col"],f["kind"],repr(f)))
    return {"status":"PASS","parser":"python.stdlib.ast.v0.2","facts":v.facts,
            "parser_claim":"frozen stdlib AST semantics plus recursive call observability under returned expressions"}
