from __future__ import annotations

import ast
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .overlay_common import _span_tuple
from .overlay_control import _line_starts, _offset_of, _mask_brace_language, _match_delim

def _python_label(node: ast.AST | None) -> str | None:
    if node is None: return None
    if isinstance(node,ast.Name): return node.id
    if isinstance(node,ast.Attribute):
        base=_python_label(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node,ast.Subscript):
        base=_python_label(node.value)
        if base:
            if isinstance(node.slice,ast.Constant) and isinstance(node.slice.value,(str,int)):
                return f"{base}[{node.slice.value!r}]"
            return f"{base}[]"
    return None


def _python_labels(node: ast.AST | None) -> List[str]:
    if node is None: return []
    out=set()
    for n in ast.walk(node):
        x=_python_label(n)
        if x: out.add(x)
    return sorted(out)


def _augment_python_field_binds(source: str, facts: Sequence[Mapping[str,Any]]) -> List[Dict[str,Any]]:
    rows=[dict(f) for f in facts]
    existing={(str(f.get("kind")),_span_tuple(f),str(f.get("field",""))) for f in rows}
    tree=ast.parse(source)
    stack: List[str]=[]
    class V(ast.NodeVisitor):
        def visit_FunctionDef(self,node:ast.FunctionDef) -> Any:
            stack.append(node.name); self.generic_visit(node); stack.pop()
        visit_AsyncFunctionDef=visit_FunctionDef
        def visit_Dict(self,node:ast.Dict) -> Any:
            scope=stack[-1] if stack else "<module>"
            for k,v in zip(node.keys,node.values):
                if isinstance(k,ast.Constant) and isinstance(k.value,str):
                    sp=(v.lineno,v.col_offset,v.end_lineno,v.end_col_offset)
                    key=("FIELD_BIND",sp,k.value)
                    if key not in existing:
                        rows.append({"kind":"FIELD_BIND","scope":scope,
                                     "span":{"start_line":sp[0],"start_col":sp[1],"end_line":sp[2],"end_col":sp[3]},
                                     "container":"dict","field":k.value,"rhs":_python_labels(v),"overlay_supplement":True})
                        existing.add(key)
            self.generic_visit(node)
    V().visit(tree)
    rows.sort(key=lambda f:(_span_tuple(f),str(f.get("kind")),repr(sorted(f.items()))))
    return rows


def _call_argument_index(source: str, outer: Tuple[int,int,int,int], inner: Tuple[int,int,int,int]) -> int | None:
    starts=_line_starts(source)
    oa=_offset_of(starts,outer[0],outer[1]); ob=_offset_of(starts,outer[2],outer[3])
    ia=_offset_of(starts,inner[0],inner[1])
    text=source[oa:ob]
    masked=_mask_brace_language(text)
    op=masked.find("(")
    if op<0: return None
    cp=_match_delim(masked,op,"(",")")
    if cp is None: return None
    rel=ia-oa
    depth=0; start=op+1; idx=0
    for i in range(op+1,cp+1):
        c=masked[i] if i < len(masked) else ","
        if c in "([{": depth+=1
        elif c in ")]}":
            if c==")" and i==cp and depth==0:
                pass
            else: depth=max(0,depth-1)
        if (c=="," and depth==0) or i==cp:
            end=i
            if start <= rel <= end: return idx
            idx+=1; start=i+1
    return None
