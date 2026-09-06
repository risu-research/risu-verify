from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence, Tuple

from .acquisition import AcquiredFile
from .frontend_python import extract as extract_python
from .frontend_js import extract as extract_js
from .frontend_go import extract_many as extract_go_many
from .model import GraphBuilder, Span, digest

def _span(path: str, sha256: str, raw: Mapping[str, Any]) -> Span:
    return Span(
        path=path,
        start_line=max(1, int(raw.get("start_line", 1))),
        start_col=max(0, int(raw.get("start_col", 0))),
        end_line=max(1, int(raw.get("end_line", raw.get("start_line", 1)))),
        end_col=max(0, int(raw.get("end_col", raw.get("start_col", 0) + 1))),
        sha256=sha256,
    )

class Normalizer:
    def __init__(self) -> None:
        self.g = GraphBuilder()
        self.coords: Dict[Tuple[str,str,str,str], str] = {}
        self.functions: Dict[str, List[Dict[str, Any]]] = {}
        self.calls: List[Dict[str, Any]] = []

    def evidence(self, span: Span, parser: str, fact_kind: str) -> str:
        return self.g.add_node(
            "EVIDENCE",
            f"{span.path}:{span.start_line}:{span.start_col}-{span.end_line}:{span.end_col}",
            span,
            parser=parser,
            fact_kind=fact_kind,
            source_sha256=span.sha256,
        )

    def coord(self, path: str, scope: str, label: str, span: Span, ev: str, *, kind: str = "SEMANTIC_COORDINATE", role: str = "symbol") -> str:
        clean = label.strip()
        key = (path, scope, clean, kind)
        if key not in self.coords:
            nid = self.g.add_node(kind, clean, span, scope=scope, role=role, symbol_key=f"{path}::{scope}::{clean}")
            self.coords[key] = nid
        nid = self.coords[key]
        self.g.add_edge("EVIDENCED_BY", nid, ev, span, evidence_role="occurrence")
        return nid

    def operation(self, label: str, span: Span, ev: str, **attrs: Any) -> str:
        nid = self.g.add_node("OPERATION", label, span, **attrs)
        self.g.add_edge("EVIDENCED_BY", nid, ev, span, evidence_role="syntactic_construct")
        return nid

    def guard(self, label: str, span: Span, ev: str, **attrs: Any) -> str:
        nid = self.g.add_node("GUARD", label, span, **attrs)
        self.g.add_edge("EVIDENCED_BY", nid, ev, span, evidence_role="syntactic_construct")
        return nid

    def add_fact(self, path: str, sha256: str, parser: str, fact: Mapping[str, Any]) -> None:
        kind = fact["kind"]
        scope = str(fact.get("scope", "<module>"))
        sp = _span(path, sha256, fact.get("span", {}))
        ev = self.evidence(sp, parser, kind)

        if kind == "FUNCTION":
            name = str(fact["name"])
            fn = self.operation(f"function:{name}", sp, ev, scope="<module>", operation_role="function_definition", name=name)
            params = []
            for idx, p in enumerate(fact.get("params", [])):
                pid = self.coord(path, name, str(p), sp, ev, kind="INPUT", role="function_parameter")
                self.g.add_edge("BINDS_TO", pid, fn, sp, binding="parameter", parameter_index=idx)
                params.append(pid)
            self.functions.setdefault(name, []).append({"node": fn, "params": params, "path": path, "scope": name})
            return

        if kind == "ASSIGN":
            lhs_ids = [self.coord(path, scope, str(x), sp, ev, role="assignment_target") for x in fact.get("lhs", [])]
            rhs_ids = [self.coord(path, scope, str(x), sp, ev, role="assignment_source") for x in fact.get("rhs", [])]
            for src in rhs_ids:
                for dst in lhs_ids:
                    self.g.add_edge("DERIVES", src, dst, sp, derivation="assignment")
            return

        if kind == "FIELD_BIND":
            container = str(fact.get("container", "object"))
            field = str(fact.get("field", "<field>"))
            field_id = self.coord(path, scope, f"{container}.{field}", sp, ev, role="field_or_wire_coordinate")
            for x in fact.get("rhs", []):
                src = self.coord(path, scope, str(x), sp, ev, role="field_source")
                self.g.add_edge("DERIVES", src, field_id, sp, derivation="field_binding", field=field)
                self.g.add_edge("BINDS_TO", src, field_id, sp, binding="representation_field", field=field)
            return

        if kind == "CALL":
            callee = str(fact.get("callee") or "<dynamic>")
            op = self.operation(f"call:{callee}", sp, ev, scope=scope, operation_role="call", callee=callee)
            arg_nodes: List[List[str]] = []
            for idx, group in enumerate(fact.get("args", [])):
                ids = [self.coord(path, scope, str(x), sp, ev, role="call_argument") for x in group]
                for src in ids:
                    self.g.add_edge("CARRIES", src, op, sp, carrier_boundary="call_argument", argument_index=idx)
                arg_nodes.append(ids)
            for key, group in sorted((fact.get("kwargs") or {}).items()):
                field = self.coord(path, scope, f"{callee}.{key}", sp, ev, role="keyword_or_field_coordinate")
                for x in group:
                    src = self.coord(path, scope, str(x), sp, ev, role="keyword_argument")
                    self.g.add_edge("DERIVES", src, field, sp, derivation="keyword_binding", field=key)
                    self.g.add_edge("CARRIES", field, op, sp, carrier_boundary="keyword_argument", field=key)
            result_nodes = [self.coord(path, scope, str(x), sp, ev, role="call_result_target") for x in fact.get("result_labels", [])]
            for dst in result_nodes:
                self.g.add_edge("DERIVES", op, dst, sp, derivation="call_result")
            self.calls.append({"callee": callee, "node": op, "args": arg_nodes, "span": sp, "path": path, "scope": scope})
            return

        if kind == "COMPARE":
            operators = [str(x) for x in fact.get("operators", [])]
            guard = self.guard(f"compare:{','.join(operators) or 'comparison'}", sp, ev, scope=scope, operators=operators)
            for idx, group in enumerate(fact.get("operands", [])):
                for x in group:
                    src = self.coord(path, scope, str(x), sp, ev, role="comparison_operand")
                    self.g.add_edge("COMPARES", src, guard, sp, operand_index=idx, operators=operators)
            return

        if kind == "IF_GUARD":
            guard = self.guard("if_guard", sp, ev, scope=scope, guard_role="control_condition")
            for x in fact.get("condition", []):
                src = self.coord(path, scope, str(x), sp, ev, role="guard_input")
                self.g.add_edge("COMPARES", src, guard, sp, operand_index=-1, operators=["CONTROL_CONDITION"])
            return

        if kind == "RETURN":
            op = self.operation(f"return:{scope}", sp, ev, scope=scope, operation_role="return_boundary")
            for x in fact.get("values", []):
                src = self.coord(path, scope, str(x), sp, ev, role="return_value")
                self.g.add_edge("DERIVES", src, op, sp, derivation="return_value")
            return

    def link_calls(self) -> None:
        # Carrier-neutral interprocedural binding: only unique acquired definitions are linked.
        for call in self.calls:
            callee = call["callee"]
            simple = callee.split(".")[-1]
            defs = self.functions.get(simple, [])
            if len(defs) != 1:
                continue
            fn = defs[0]
            sp = call["span"]
            self.g.add_edge("BINDS_TO", call["node"], fn["node"], sp, binding="unique_acquired_function_definition", callee=simple)
            for idx, group in enumerate(call["args"]):
                if idx >= len(fn["params"]):
                    break
                param = fn["params"][idx]
                for src in group:
                    self.g.add_edge("BINDS_TO", src, param, sp, binding="call_argument_to_parameter", argument_index=idx, callee=simple)

def build_ir(
    acquired: Sequence[AcquiredFile],
    *,
    acquisition_doc: Mapping[str, Any],
    go_helper_path: Path,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    normal = Normalizer()
    frontend_status: List[Dict[str, Any]] = []
    go_rows = [{"path": r.path, "data": r.data} for r in acquired if r.language == "go"]
    go_map = extract_go_many(go_rows, go_helper_path)

    for row in sorted(acquired, key=lambda x: x.path):
        text = row.data.decode("utf-8")
        if row.language == "python":
            parsed = extract_python(text)
        elif row.language == "go":
            parsed = go_map[row.path]
        elif row.language == "typescript_javascript":
            parsed = extract_js(text)
        else:
            parsed = {"status":"MATERIAL_PARSE_FAILURE","parser":"none","error":"UNSUPPORTED_MATERIAL_LANGUAGE","facts":[]}
        frontend_status.append({
            "path": row.path,
            "sha256": row.sha256,
            "language": row.language,
            "status": parsed.get("status"),
            "parser": parsed.get("parser"),
            "error": parsed.get("error"),
            "fact_count": len(parsed.get("facts", [])),
        })
        if parsed.get("status") != "PASS":
            continue
        for fact in parsed.get("facts", []):
            normal.add_fact(row.path, row.sha256, str(parsed.get("parser")), fact)

    normal.link_calls()
    files = [r.record() for r in sorted(acquired, key=lambda x: x.path)]
    ir = normal.g.as_document(files=files, acquisition=acquisition_doc, frontend_status=frontend_status)
    parse_failures = [x for x in frontend_status if x["status"] != "PASS"]
    if acquisition_doc.get("status") == "INFRASTRUCTURE_INVALID_BEFORE_PREDICTION":
        status = {"status":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","reason":acquisition_doc.get("reason")}
    elif parse_failures:
        status = {"status":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","reason":"MATERIAL_PARSE_FAILURE","paths":[x["path"] for x in parse_failures]}
    elif acquisition_doc.get("status") != "PASS":
        status = {"status":"E2_PREDICTED_ASSURANCE_INCOMPLETE","reason":acquisition_doc.get("reason")}
    else:
        status = {"status":"PASS","reason":"A1_A2_STRUCTURAL_IR_BUILT"}
    status["semantic_authority"] = False
    status["ir_digest_sha256"] = ir["ir_digest_sha256"]
    status["frontend_digest_sha256"] = digest(frontend_status)
    return ir, status
