from __future__ import annotations

import re
from typing import Any, Dict, List, Sequence, Tuple

IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
MEMBER = rf"{IDENT}(?:\s*\.\s*{IDENT})*"
FUNC_RE = re.compile(rf"\b(?:export\s+)?(?:async\s+)?function\s+({IDENT})\s*\(([^)]*)\)")
ARROW_RE = re.compile(rf"\b(?:export\s+)?(?:const|let|var)\s+({IDENT})\s*(?::[^=;\n]+)?=\s*(?:async\s*)?\(([^)]*)\)\s*=>")
CALL_RE = re.compile(rf"({MEMBER})\s*\(")
MEMBER_RE = re.compile(MEMBER)
COMPARE_EXPR_RE = re.compile(rf"(?<![\w$])({MEMBER})\s*(===|!==|==|!=|<=|>=|<|>)\s*({MEMBER})(?![\w$])")
DECL_ASSIGN_RE = re.compile(rf"\b(?:const|let|var)\s+({IDENT})(?:\s*:[^=;\n]+)?\s*=\s*([^;\n]+)")
SIMPLE_ASSIGN_RE = re.compile(rf"(?<![\w$])({MEMBER})\s*=(?!=|>)\s*([^;\n]+)")
OBJECT_PAIR_RE = re.compile(rf"({IDENT}|[\"'][^\"']+[\"'])\s*:\s*([^,}}]+)")
SHORTHAND_RE = re.compile(rf"(?<![:.\w$])({IDENT})(?=\s*[,}}])")
RETURN_KW_RE = re.compile(r"\breturn\b")
IF_KW_RE = re.compile(r"\bif\s*\(")
RESERVED = {
    "if","for","while","switch","return","function","const","let","var","new",
    "true","false","null","undefined","async","await","typeof","instanceof",
    "Object","JSON","String","Number","Boolean","Array","Promise","console","process",
}


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last = text.rfind("\n", 0, offset)
    return line, offset if last < 0 else offset - last - 1


def _span(text: str, start: int, end: int) -> Dict[str, int]:
    sl, sc = _line_col(text, start)
    el, ec = _line_col(text, max(start, end))
    return {"start_line": sl, "start_col": sc, "end_line": el, "end_col": ec}


def _mask_comments(text: str) -> str:
    out = list(text)
    i = 0
    quote = None
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                if out[i] != "\n": out[i] = " "
                if i + 1 < len(out) and out[i + 1] != "\n": out[i + 1] = " "
                i += 2
                continue
            if c == quote:
                quote = None
            else:
                if out[i] != "\n": out[i] = " "
            i += 1
            continue
        if c in {"'", '"', "`"}:
            quote = c
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            if j < 0: j = len(text)
            for k in range(i, j): out[k] = " "
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0: j = len(text) - 2
            end = min(len(text), j + 2)
            for k in range(i, end):
                if out[k] != "\n": out[k] = " "
            i = end
            continue
        i += 1
    return "".join(out)


def _labels(expr: str) -> List[str]:
    out = set()
    for m in MEMBER_RE.finditer(expr):
        x = re.sub(r"\s+", "", m.group(0))
        if x.split(".", 1)[0] not in RESERVED:
            out.add(x)
    return sorted(out)


def _param_name(raw: str) -> str | None:
    x = raw.strip()
    if not x: return None
    x = re.sub(r"^(?:public|private|protected|readonly)\s+", "", x)
    x = x.lstrip(".")
    x = x.split("=", 1)[0].strip()
    x = x.split(":", 1)[0].strip()
    x = x.rstrip("?").strip()
    m = re.match(IDENT, x)
    return m.group(0) if m else None


def _find_matching(text: str, open_pos: int, left: str, right: str) -> int | None:
    if open_pos < 0 or open_pos >= len(text) or text[open_pos] != left:
        return None
    depth = 0
    i = open_pos
    while i < len(text):
        c = text[i]
        if c == left:
            depth += 1
        elif c == right:
            depth -= 1
            if depth == 0: return i
        i += 1
    return None


def _trim_right(text: str, start: int, end: int) -> int:
    while end > start and text[end - 1] in " \t\r": end -= 1
    return end


def _function_rows(source: str, masked: str) -> List[Dict[str, Any]]:
    rows=[]
    for reg, form in ((FUNC_RE,"function_declaration"),(ARROW_RE,"arrow_declaration")):
        for m in reg.finditer(masked):
            body_open = masked.find("{", m.end())
            body_close = _find_matching(masked, body_open, "{", "}") if body_open >= 0 else None
            if body_close is None:
                continue
            name=m.group(1)
            params=[p for p in (_param_name(x) for x in m.group(2).split(",")) if p]
            rows.append({"name":name,"params":params,"header_start":m.start(),"header_end":m.end(),
                         "body_open":body_open,"body_close":body_close,"full_end":body_close+1,"form":form})
    rows.sort(key=lambda r:(r["header_start"],r["full_end"],r["name"]))
    return rows


def _scope_at(functions: Sequence[Dict[str,Any]], pos: int) -> str:
    owned=[r for r in functions if r["body_open"] < pos < r["body_close"]]
    if not owned: return "<module>"
    row=min(owned,key=lambda r:(r["body_close"]-r["body_open"],r["body_open"],r["name"]))
    return str(row["name"])


def _return_rows(source: str, masked: str, functions: Sequence[Dict[str,Any]]) -> List[Dict[str,Any]]:
    out=[]
    for m in RETURN_KW_RE.finditer(masked):
        start=m.start(); i=m.end()
        while i < len(masked) and masked[i] in " \t\r": i += 1
        expr_start=i
        dp=db=dc=0
        end=None; expr_end=None
        while i < len(masked):
            c=masked[i]
            if c=="(": dp+=1
            elif c==")": dp=max(0,dp-1)
            elif c=="[": db+=1
            elif c=="]": db=max(0,db-1)
            elif c=="{": dc+=1
            elif c=="}":
                if dc>0: dc-=1
                elif dp==0 and db==0:
                    expr_end=_trim_right(source,expr_start,i); end=expr_end; break
            if dp==0 and db==0 and dc==0:
                if c==";":
                    expr_end=_trim_right(source,expr_start,i); end=i+1; break
                if c=="\n":
                    expr_end=_trim_right(source,expr_start,i); end=expr_end; break
            i+=1
        if end is None:
            expr_end=_trim_right(source,expr_start,len(source)); end=expr_end
        if end < m.end(): end=m.end()
        out.append({"start":start,"end":end,"expr_start":expr_start,"expr_end":expr_end,
                    "scope":_scope_at(functions,start)})
    return out


def _if_rows(source: str, masked: str, functions: Sequence[Dict[str,Any]]) -> List[Dict[str,Any]]:
    rows=[]
    for m in IF_KW_RE.finditer(masked):
        op=masked.find("(",m.start(),m.end()+1)
        cp=_find_matching(masked,op,"(",")") if op>=0 else None
        if cp is None: continue
        rows.append({"start":m.start(),"open":op,"close":cp,"cond_start":op+1,"cond_end":cp,
                     "scope":_scope_at(functions,m.start())})
    return rows


def _split_arg_ranges(masked: str, open_pos: int, close_pos: int) -> List[Tuple[int,int]]:
    if close_pos <= open_pos+1: return []
    out=[]; start=open_pos+1; dp=db=dc=0
    i=start
    while i <= close_pos:
        c=masked[i] if i < close_pos else ","
        if c=="(": dp+=1
        elif c==")": dp=max(0,dp-1)
        elif c=="[": db+=1
        elif c=="]": db=max(0,db-1)
        elif c=="{": dc+=1
        elif c=="}": dc=max(0,dc-1)
        if c=="," and dp==0 and db==0 and dc==0:
            a=start; b=i
            while a<b and masked[a] in " \t\r\n": a+=1
            while b>a and masked[b-1] in " \t\r\n": b-=1
            if a<b: out.append((a,b))
            start=i+1
        i+=1
    return out


def _declaration_like_call(masked: str, functions: Sequence[Dict[str,Any]], start: int, close: int, callee: str) -> bool:
    for r in functions:
        if r["header_start"] <= start < r["body_open"] and str(r["name"])==callee.split(".")[-1]:
            return True
    j=close+1
    while j < len(masked) and masked[j] in " \t\r\n": j+=1
    if j < len(masked) and masked[j]=="{":
        return True
    return False


def _object_binds(source: str, masked: str, functions: Sequence[Dict[str,Any]]) -> List[Dict[str,Any]]:
    facts=[]
    for i,c in enumerate(masked):
        if c!="{": continue
        j=_find_matching(masked,i,"{","}")
        if j is None or j-i>2000: continue
        body=source[i+1:j]
        scope="<lexical>"
        for m in OBJECT_PAIR_RE.finditer(body):
            field=m.group(1).strip("\"'"); rhs=m.group(2)
            s=i+1+m.start(); e=i+1+m.end()
            facts.append({"kind":"FIELD_BIND","scope":scope,"span":_span(source,s,e),
                          "container":"object","field":field,"rhs":_labels(rhs)})
        if ":" in body or "," in body:
            for m in SHORTHAND_RE.finditer(body):
                name=m.group(1)
                if name in RESERVED: continue
                s=i+1+m.start(); e=i+1+m.end()
                facts.append({"kind":"FIELD_BIND","scope":scope,"span":_span(source,s,e),
                              "container":"object","field":name,"rhs":[name],"shorthand":True})
    return facts


def extract(source: str) -> Dict[str, Any]:
    masked=_mask_comments(source)
    for l,r in [("(",")"),("{","}"),("[","]")]:
        if masked.count(l)!=masked.count(r):
            return {"status":"MATERIAL_PARSE_FAILURE","parser":"e2.js-ts.structural.v0.2",
                    "error":f"UNBALANCED_{l}{r}","facts":[],
                    "parser_claim":"bounded structural extraction; ambiguous constructs fail closed"}

    functions=_function_rows(source,masked)
    facts=[]
    for r in functions:
        facts.append({"kind":"FUNCTION","scope":"<module>","span":_span(source,r["header_start"],r["full_end"]),
                      "name":r["name"],"params":r["params"],"declaration_form":r["form"]})

    comparison_contexts: List[Tuple[int,int,str]]=[]

    for m in DECL_ASSIGN_RE.finditer(masked):
        rhs_start,rhs_end=m.start(2),m.end(2)
        facts.append({"kind":"ASSIGN","scope":_scope_at(functions,m.start()),"span":_span(source,m.start(),m.end()),
                      "lhs":[m.group(1)],"rhs":_labels(source[rhs_start:rhs_end]),"value_kind":"lexical"})
        comparison_contexts.append((rhs_start,rhs_end,_scope_at(functions,m.start())))
    for m in SIMPLE_ASSIGN_RE.finditer(masked):
        if re.search(r"\b(?:const|let|var)\s+$", masked[max(0,m.start()-12):m.start()]): continue
        rhs_start,rhs_end=m.start(2),m.end(2)
        facts.append({"kind":"ASSIGN","scope":_scope_at(functions,m.start()),"span":_span(source,m.start(),m.end()),
                      "lhs":[re.sub(r"\s+","",m.group(1))],"rhs":_labels(source[rhs_start:rhs_end]),"value_kind":"lexical"})
        comparison_contexts.append((rhs_start,rhs_end,_scope_at(functions,m.start())))

    for m in CALL_RE.finditer(masked):
        callee=re.sub(r"\s+","",m.group(1))
        if callee in {"if","for","while","switch","function"}: continue
        op=masked.find("(",m.start(1)+len(m.group(1)))
        cp=_find_matching(masked,op,"(",")") if op>=0 else None
        if cp is None or _declaration_like_call(masked,functions,m.start(),cp,callee): continue
        ranges=_split_arg_ranges(masked,op,cp)
        args=[_labels(source[a:b]) for a,b in ranges]
        scope=_scope_at(functions,m.start())
        facts.append({"kind":"CALL","scope":scope,"span":_span(source,m.start(),cp+1),
                      "callee":callee,"args":args,"kwargs":{},"result_labels":[]})
        for a,b in ranges: comparison_contexts.append((a,b,scope))

    if_rows=_if_rows(source,masked,functions)
    for r in if_rows:
        cond=source[r["cond_start"]:r["cond_end"]]
        facts.append({"kind":"IF_GUARD","scope":r["scope"],"span":_span(source,r["cond_start"],r["cond_end"]),
                      "condition":_labels(cond),"body_span":_span(source,r["start"],r["close"]+1)})
        comparison_contexts.append((r["cond_start"],r["cond_end"],r["scope"]))

    returns=_return_rows(source,masked,functions)
    for r in returns:
        expr=source[r["expr_start"]:r["expr_end"]]
        facts.append({"kind":"RETURN","scope":r["scope"],"span":_span(source,r["start"],r["end"]),
                      "values":_labels(expr)})
        if r["expr_start"]<r["expr_end"]:
            comparison_contexts.append((r["expr_start"],r["expr_end"],r["scope"]))

    compare_seen=set()
    for a,b,scope in comparison_contexts:
        segment=masked[a:b]
        for m in COMPARE_EXPR_RE.finditer(segment):
            left=re.sub(r"\s+","",m.group(1)); right=re.sub(r"\s+","",m.group(3)); op=m.group(2)
            if left.split(".",1)[0] in RESERVED or right.split(".",1)[0] in RESERVED: continue
            s=a+m.start(); e=a+m.end(); key=(s,e,op,scope,left,right)
            if key in compare_seen: continue
            compare_seen.add(key)
            facts.append({"kind":"COMPARE","scope":scope,"span":_span(source,s,e),
                          "operands":[[left],[right]],"operators":[op]})

    facts.extend(_object_binds(source,masked,functions))
    dedup={}
    for f in facts:
        key=repr(sorted(f.items(),key=lambda x:x[0])); dedup[key]=f
    facts=list(dedup.values())
    facts.sort(key=lambda f:(f["span"]["start_line"],f["span"]["start_col"],f["kind"],repr(f)))
    return {"status":"PASS","parser":"e2.js-ts.structural.v0.2","facts":facts,
            "parser_claim":"versioned bounded structural extraction; declaration-aware CALLs, expression-context COMPAREs, canonical balanced RETURN spans; unsupported ambiguity fails closed"}
