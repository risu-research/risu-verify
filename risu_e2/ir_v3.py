from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from .acquisition import AcquiredFile
from .frontend_python_v2 import extract as extract_python
from .frontend_js_v3 import extract as extract_js
from .frontend_go import extract_many as extract_go_many
from .ir import Normalizer
from .model import digest


def build_ir(
    acquired: Sequence[AcquiredFile],
    *,
    acquisition_doc: Mapping[str, Any],
    go_helper_path: Path,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    normal=Normalizer()
    frontend_status=[]
    go_rows=[{"path":r.path,"data":r.data} for r in acquired if r.language=="go"]
    go_map=extract_go_many(go_rows,go_helper_path)

    for row in sorted(acquired,key=lambda x:x.path):
        text=row.data.decode("utf-8")
        if row.language=="python": parsed=extract_python(text)
        elif row.language=="go": parsed=go_map[row.path]
        elif row.language=="typescript_javascript": parsed=extract_js(text)
        else: parsed={"status":"MATERIAL_PARSE_FAILURE","parser":"none","error":"UNSUPPORTED_MATERIAL_LANGUAGE","facts":[]}
        frontend_status.append({"path":row.path,"sha256":row.sha256,"language":row.language,
                                "status":parsed.get("status"),"parser":parsed.get("parser"),
                                "error":parsed.get("error"),"fact_count":len(parsed.get("facts",[]))})
        if parsed.get("status")!="PASS": continue
        for fact in parsed.get("facts",[]):
            normal.add_fact(row.path,row.sha256,str(parsed.get("parser")),fact)

    normal.link_calls()
    files=[r.record() for r in sorted(acquired,key=lambda x:x.path)]
    ir=normal.g.as_document(files=files,acquisition=acquisition_doc,frontend_status=frontend_status)
    parse_failures=[x for x in frontend_status if x["status"]!="PASS"]
    if acquisition_doc.get("status")=="INFRASTRUCTURE_INVALID_BEFORE_PREDICTION":
        status={"status":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","reason":acquisition_doc.get("reason")}
    elif parse_failures:
        status={"status":"INFRASTRUCTURE_INVALID_BEFORE_PREDICTION","reason":"MATERIAL_PARSE_FAILURE","paths":[x["path"] for x in parse_failures]}
    elif acquisition_doc.get("status")!="PASS":
        status={"status":"E2_PREDICTED_ASSURANCE_INCOMPLETE","reason":acquisition_doc.get("reason")}
    else:
        status={"status":"PASS","reason":"A1_A2_STRUCTURAL_IR_BUILT_V0_3_FRONTEND_SURFACE"}
    status["semantic_authority"]=False
    status["ir_digest_sha256"]=ir["ir_digest_sha256"]
    status["frontend_digest_sha256"]=digest(frontend_status)
    status["frontend_surface_version"]="v0.3"
    status["python_frontend_surface_version"]="v0.2-reused"
    return ir,status
