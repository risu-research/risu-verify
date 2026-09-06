from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from .overlay_common import _contains, _span_tuple

@dataclass
class CStmt:
    kind: str
    span: Tuple[int,int,int,int]
    condition_span: Tuple[int,int,int,int] | None = None
    then_body: List["CStmt"] | None = None
    else_body: List["CStmt"] | None = None


def _line_starts(text: str) -> List[int]:
    out = [0]
    for i,c in enumerate(text):
        if c == "\n": out.append(i+1)
    return out


def _offset_of(starts: Sequence[int], line: int, col: int) -> int:
    return starts[line-1] + col


def _pos_of(starts: Sequence[int], offset: int) -> Tuple[int,int]:
    import bisect
    line_idx = bisect.bisect_right(starts, offset) - 1
    return (line_idx+1, offset-starts[line_idx])


def _span_from_offsets(starts: Sequence[int], a: int, b: int) -> Tuple[int,int,int,int]:
    sl,sc = _pos_of(starts,a); el,ec = _pos_of(starts,b)
    return (sl,sc,el,ec)


def _mask_brace_language(text: str) -> str:
    out = list(text)
    i = 0; quote: str | None = None
    while i < len(text):
        c = text[i]
        if quote is not None:
            if c == "\\" and quote != "`":
                if out[i] != "\n": out[i] = " "
                if i+1 < len(out) and out[i+1] != "\n": out[i+1] = " "
                i += 2; continue
            if c == quote:
                quote = None
            if out[i] != "\n": out[i] = " "
            i += 1; continue
        if c in {'"', "'", '`'}:
            quote = c
            out[i] = " "; i += 1; continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            if j < 0: j = len(text)
            for k in range(i,j): out[k] = " "
            i = j; continue
        if text.startswith("/*", i):
            j = text.find("*/", i+2)
            if j < 0: j = len(text)-2
            end = min(len(text), j+2)
            for k in range(i,end):
                if out[k] != "\n": out[k] = " "
            i = end; continue
        i += 1
    return "".join(out)


def _match_delim(masked: str, open_pos: int, left: str, right: str) -> int | None:
    depth = 0
    for i in range(open_pos, len(masked)):
        c = masked[i]
        if c == left: depth += 1
        elif c == right:
            depth -= 1
            if depth == 0: return i
    return None


def _strip_paren_span(masked: str, a: int, b: int) -> Tuple[int,int]:
    while a < b and masked[a].isspace(): a += 1
    while b > a and masked[b-1].isspace(): b -= 1
    if a < b and masked[a] == "(" and masked[b-1] == ")":
        close = _match_delim(masked, a, "(", ")")
        if close == b-1:
            a += 1; b -= 1
            while a < b and masked[a].isspace(): a += 1
            while b > a and masked[b-1].isspace(): b -= 1
    return a,b


def _parse_brace_block(text: str, masked: str, starts: Sequence[int], a: int, b: int, language: str) -> Tuple[List[CStmt], List[str]]:
    stmts: List[CStmt] = []; unsupported: List[str] = []
    i = a
    unsupported_words = ("for","switch","select","go","defer","range") if language == "go" else ("for","while","switch","try","catch","finally","throw","await","yield","do")
    def skip(pos: int) -> int:
        while pos < b and masked[pos].isspace(): pos += 1
        return pos
    def word_at(pos: int, word: str) -> bool:
        if not masked.startswith(word,pos): return False
        before = masked[pos-1] if pos>0 else " "
        after = masked[pos+len(word)] if pos+len(word)<len(masked) else " "
        return not (before.isalnum() or before in "_$.") and not (after.isalnum() or after in "_$")
    while True:
        i = skip(i)
        if i >= b: break
        bad = next((w for w in unsupported_words if word_at(i,w)), None)
        if bad:
            unsupported.append(bad)
        if word_at(i,"if"):
            cond_a = i+2
            j = cond_a
            depth = 0
            body_open = None
            while j < b:
                c = masked[j]
                if c == "(": depth += 1
                elif c == ")": depth = max(0,depth-1)
                elif c == "{" and depth == 0:
                    body_open = j; break
                j += 1
            if body_open is None:
                unsupported.append("if_without_braced_body"); break
            body_close = _match_delim(masked, body_open, "{", "}")
            if body_close is None or body_close > b:
                unsupported.append("unbalanced_if_body"); break
            ca,cb = _strip_paren_span(masked, cond_a, body_open)
            then_body, sub_bad = _parse_brace_block(text,masked,starts,body_open+1,body_close,language)
            unsupported.extend(sub_bad)
            end = body_close+1
            k = skip(end)
            else_body: List[CStmt] = []
            if word_at(k,"else"):
                k = skip(k+4)
                if k < b and masked[k] == "{":
                    ec = _match_delim(masked,k,"{","}")
                    if ec is None: unsupported.append("unbalanced_else_body")
                    else:
                        else_body, sub_bad = _parse_brace_block(text,masked,starts,k+1,ec,language)
                        unsupported.extend(sub_bad); end = ec+1
                else:
                    unsupported.append("unbraced_else")
            stmts.append(CStmt("IF",_span_from_offsets(starts,i,end),_span_from_offsets(starts,ca,cb),then_body,else_body))
            i = end; continue
        if word_at(i,"return"):
            j = i+6; par=brack=brace=0
            while j < b:
                c=masked[j]
                if c=="(": par+=1
                elif c==")": par=max(0,par-1)
                elif c=="[": brack+=1
                elif c=="]": brack=max(0,brack-1)
                elif c=="{": brace+=1
                elif c=="}":
                    if brace>0: brace-=1
                    elif par==0 and brack==0: break
                if par==0 and brack==0 and brace==0 and ((language!="go" and c==";") or c=="\n"):
                    if c==";": j+=1
                    break
                j+=1
            stmts.append(CStmt("RETURN",_span_from_offsets(starts,i,j)))
            i=j; continue
        j=i; par=brack=brace=0
        while j < b:
            c=masked[j]
            if c=="(": par+=1
            elif c==")": par=max(0,par-1)
            elif c=="[": brack+=1
            elif c=="]": brack=max(0,brack-1)
            elif c=="{": brace+=1
            elif c=="}":
                if brace>0: brace-=1
                else: break
            if par==0 and brack==0 and brace==0 and ((language!="go" and c==";") or c=="\n"):
                if c==";": j+=1
                break
            j+=1
        if j <= i:
            unsupported.append("unparsed_statement"); break
        stmts.append(CStmt("SIMPLE",_span_from_offsets(starts,i,j)))
        i=j
    return stmts, sorted(set(unsupported))


def _python_stmt(node: ast.stmt) -> CStmt:
    sp = (node.lineno,node.col_offset,node.end_lineno,node.end_col_offset)
    if isinstance(node, ast.If):
        test = node.test
        tsp = (test.lineno,test.col_offset,test.end_lineno,test.end_col_offset)
        return CStmt("IF",sp,tsp,[_python_stmt(x) for x in node.body],[_python_stmt(x) for x in node.orelse])
    if isinstance(node, ast.Return): return CStmt("RETURN",sp)
    return CStmt("SIMPLE",sp)


def _control_functions(source: str, language: str, function_facts: Sequence[Mapping[str,Any]]) -> Dict[str, Dict[str,Any]]:
    out: Dict[str,Dict[str,Any]] = {}
    if language == "python":
        tree = ast.parse(source)
        for n in ast.walk(tree):
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
                bad_types=(ast.For,ast.AsyncFor,ast.While,ast.Try,ast.With,ast.AsyncWith,ast.Match,ast.Raise,ast.Await,ast.Yield,ast.YieldFrom,ast.Break,ast.Continue)
                unsupported=sorted({type(x).__name__ for x in ast.walk(n) if isinstance(x,bad_types)})
                out[n.name]={"span":(n.lineno,n.col_offset,n.end_lineno,n.end_col_offset),"stmts":[_python_stmt(x) for x in n.body],"unsupported":unsupported,"order_source":"python.ast"}
        return out
    starts=_line_starts(source); masked=_mask_brace_language(source)
    lang = "go" if language=="go" else "js"
    for f in function_facts:
        name=str(f.get("name")); sp=_span_tuple(f)
        sa=_offset_of(starts,sp[0],sp[1]); sb=_offset_of(starts,sp[2],sp[3])
        body_open=masked.find("{",sa,sb)
        if body_open<0:
            out[name]={"span":sp,"stmts":[],"unsupported":["function_body_missing"],"order_source":f"{lang}.validated_brace_structure"}; continue
        body_close=_match_delim(masked,body_open,"{","}")
        if body_close is None or body_close>sb:
            out[name]={"span":sp,"stmts":[],"unsupported":["function_body_unbalanced"],"order_source":f"{lang}.validated_brace_structure"}; continue
        stmts,bad=_parse_brace_block(source,masked,starts,body_open+1,body_close,lang)
        out[name]={"span":sp,"stmts":stmts,"unsupported":bad,"order_source":f"{lang}.validated_brace_structure"}
    return out


def _stmt_walk(stmts: Sequence[CStmt]) -> Iterable[CStmt]:
    for s in stmts:
        yield s
        if s.then_body: yield from _stmt_walk(s.then_body)
        if s.else_body: yield from _stmt_walk(s.else_body)


def _smallest_stmt(stmts: Sequence[CStmt], span: Tuple[int,int,int,int]) -> CStmt | None:
    rows=[s for s in _stmt_walk(stmts) if _contains(s.span,span)]
    if not rows: return None
    return min(rows,key=lambda s:((s.span[2]-s.span[0])*100000+(s.span[3]-s.span[1]),s.span))


def _function_for_span(functions: Mapping[str,Mapping[str,Any]], span: Tuple[int,int,int,int]) -> str | None:
    rows=[(name,row) for name,row in functions.items() if _contains(tuple(row["span"]),span)]
    if not rows: return None
    return min(rows,key=lambda x:((x[1]["span"][2]-x[1]["span"][0])*100000+(x[1]["span"][3]-x[1]["span"][1]),x[0]))[0]
