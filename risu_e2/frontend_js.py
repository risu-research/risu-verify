from __future__ import annotations

import re
from typing import Any, Dict, List, Sequence, Tuple

IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
MEMBER = rf"{IDENT}(?:\s*\.\s*{IDENT})*"
FUNC_RE = re.compile(rf"\b(?:export\s+)?(?:async\s+)?function\s+({IDENT})\s*\(([^)]*)\)")
ARROW_RE = re.compile(rf"\b(?:export\s+)?(?:const|let|var)\s+({IDENT})\s*(?::[^=;\n]+)?=\s*(?:async\s*)?\(([^)]*)\)\s*=>")
CALL_RE = re.compile(rf"({MEMBER})\s*\(")
MEMBER_RE = re.compile(MEMBER)
COMPARE_RE = re.compile(r"(===|!==|==|!=|<=|>=|<|>)")
IF_RE = re.compile(r"\bif\s*\((.*?)\)", re.S)
RETURN_RE = re.compile(r"\breturn\b([^;\n}]*)")
DECL_ASSIGN_RE = re.compile(rf"\b(?:const|let|var)\s+({IDENT})(?:\s*:[^=;\n]+)?\s*=\s*([^;\n]+)")
SIMPLE_ASSIGN_RE = re.compile(rf"(?<![\w$])({MEMBER})\s*=(?!=|>)\s*([^;\n]+)")
OBJECT_PAIR_RE = re.compile(rf"({IDENT}|[\"'][^\"']+[\"'])\s*:\s*([^,}}]+)")
SHORTHAND_RE = re.compile(rf"(?<![:.\w$])({IDENT})(?=\s*[,}}])")
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
            for k in range(i, j):
                out[k] = " "
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
    if not x:
        return None
    x = re.sub(r"^(?:public|private|protected|readonly)\s+", "", x)
    x = x.lstrip(".")
    x = x.split("=", 1)[0].strip()
    x = x.split(":", 1)[0].strip()
    x = x.rstrip("?").strip()
    m = re.match(IDENT, x)
    return m.group(0) if m else None

def _find_matching(text: str, open_pos: int, left: str, right: str) -> int | None:
    depth = 0
    quote = None
    i = open_pos
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
            i += 1
            continue
        if c in {"'", '"', "`"}:
            quote = c
        elif c == left:
            depth += 1
        elif c == right:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None

def _object_binds(text: str, masked: str) -> List[Dict[str, Any]]:
    facts: List[Dict[str, Any]] = []
    for i, c in enumerate(masked):
        if c != "{":
            continue
        j = _find_matching(masked, i, "{", "}")
        if j is None or j - i > 2000:
            continue
        body = text[i+1:j]
        for m in OBJECT_PAIR_RE.finditer(body):
            field = m.group(1).strip("\"'")
            rhs = m.group(2)
            s = i + 1 + m.start()
            e = i + 1 + m.end()
            facts.append({"kind":"FIELD_BIND","scope":"<lexical>","span":_span(text,s,e),
                          "container":"object","field":field,"rhs":_labels(rhs)})
        # shorthand fields are useful carrier edges, but only if body looks object-like not block-like.
        if ":" in body or "," in body:
            for m in SHORTHAND_RE.finditer(body):
                name = m.group(1)
                if name in RESERVED:
                    continue
                s = i + 1 + m.start()
                e = i + 1 + m.end()
                facts.append({"kind":"FIELD_BIND","scope":"<lexical>","span":_span(text,s,e),
                              "container":"object","field":name,"rhs":[name],"shorthand":True})
    return facts

def extract(source: str) -> Dict[str, Any]:
    masked = _mask_comments(source)
    # Fast fail-closed delimiter check.
    for l, r in [("(", ")"), ("{", "}"), ("[", "]")]:
        if masked.count(l) != masked.count(r):
            return {"status":"MATERIAL_PARSE_FAILURE","parser":"e2.js-ts.structural.v0.1",
                    "error":f"UNBALANCED_{l}{r}","facts":[]}
    facts: List[Dict[str, Any]] = []
    func_spans: List[tuple[int,int,str]] = []
    for reg in (FUNC_RE, ARROW_RE):
        for m in reg.finditer(masked):
            name = m.group(1)
            params = [p for p in (_param_name(x) for x in m.group(2).split(",")) if p]
            body_open = masked.find("{", m.end())
            body_close = _find_matching(masked, body_open, "{", "}") if body_open >= 0 else None
            fn_end = body_close + 1 if body_close is not None else m.end()
            facts.append({"kind":"FUNCTION","scope":"<module>","span":_span(source,m.start(),fn_end),
                          "name":name,"params":params})
            func_spans.append((m.start(), fn_end, name))

    def scope_at(pos: int) -> str:
        # lexical function ownership is intentionally conservative; exact body binding is deferred.
        before = [x for x in func_spans if x[0] <= pos]
        return before[-1][2] if before else "<module>"

    for m in DECL_ASSIGN_RE.finditer(masked):
        lhs = [m.group(1)]
        rhs_text = source[m.start(2):m.end(2)]
        facts.append({"kind":"ASSIGN","scope":scope_at(m.start()),"span":_span(source,m.start(),m.end()),
                      "lhs":lhs,"rhs":_labels(rhs_text),"value_kind":"lexical"})
    for m in SIMPLE_ASSIGN_RE.finditer(masked):
        # avoid duplicating declarations
        if re.search(r"\b(?:const|let|var)\s+$", masked[max(0,m.start()-12):m.start()]):
            continue
        facts.append({"kind":"ASSIGN","scope":scope_at(m.start()),"span":_span(source,m.start(),m.end()),
                      "lhs":[re.sub(r"\s+","",m.group(1))],"rhs":_labels(source[m.start(2):m.end(2)]),"value_kind":"lexical"})

    for m in CALL_RE.finditer(masked):
        callee = re.sub(r"\s+", "", m.group(1))
        if callee in {"if","for","while","switch","function"}:
            continue
        open_pos = masked.find("(", m.start(1) + len(m.group(1)))
        close = _find_matching(masked, open_pos, "(", ")") if open_pos >= 0 else None
        if close is None:
            continue
        arg_text = source[open_pos+1:close]
        # Split only top-level commas.
        args, start = [], 0
        depth = 0
        quote = None
        for i,c in enumerate(arg_text):
            if quote:
                if c == "\\": continue
                if c == quote: quote=None
                continue
            if c in {"'",'"',"`"}: quote=c
            elif c in "([{": depth += 1
            elif c in ")]}": depth = max(0, depth-1)
            elif c == "," and depth == 0:
                args.append(_labels(arg_text[start:i])); start=i+1
        if arg_text.strip() or start:
            args.append(_labels(arg_text[start:]))
        facts.append({"kind":"CALL","scope":scope_at(m.start()),"span":_span(source,m.start(),close+1),
                      "callee":callee,"args":args,"kwargs":{},"result_labels":[]})

    for m in IF_RE.finditer(masked):
        cond = source[m.start(1):m.end(1)]
        facts.append({"kind":"IF_GUARD","scope":scope_at(m.start()),"span":_span(source,m.start(1),m.end(1)),
                      "condition":_labels(cond),"body_span":_span(source,m.start(),m.end())})
        ops = COMPARE_RE.findall(cond)
        if ops:
            chunks = COMPARE_RE.split(cond)
            operands = [_labels(chunks[i]) for i in range(0, len(chunks), 2)]
            facts.append({"kind":"COMPARE","scope":scope_at(m.start()),"span":_span(source,m.start(1),m.end(1)),
                          "operands":operands,"operators":ops})

    for m in RETURN_RE.finditer(masked):
        expr = source[m.start(1):m.end(1)]
        facts.append({"kind":"RETURN","scope":scope_at(m.start()),"span":_span(source,m.start(),m.end()),
                      "values":_labels(expr)})

    facts.extend(_object_binds(source, masked))
    # remove exact duplicates caused by nested scans
    dedup = {}
    for f in facts:
        key = repr(sorted(f.items(), key=lambda x:x[0]))
        dedup[key] = f
    facts = list(dedup.values())
    facts.sort(key=lambda f:(f["span"]["start_line"],f["span"]["start_col"],f["kind"],repr(f)))
    return {"status":"PASS","parser":"e2.js-ts.structural.v0.1","facts":facts,
            "parser_claim":"bounded structural extraction; unsupported ambiguity must not be promoted to semantic authority"}
