from __future__ import annotations

import ast
import base64
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Sequence

VERSION_TOKENS=("sha","etag","version","revision","generation","resource_version","resourceversion")
MUTATION_TOKENS=("update","patch","put","write","delete","create","apply","commit","save","mutate","set")
ERROR_TOKENS=("error","err","fail","reject","conflict","stale","mismatch","abort")

def canonical_bytes(v:Any)->bytes:
    return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()

def _compact(s:str)->str:
    return "".join(ch for ch in s.lower() if ch.isalnum())

def is_versionish(name:str)->bool:
    c=_compact(name)
    return any(_compact(t) in c for t in VERSION_TOKENS)

def _name_of(node:ast.AST)->str|None:
    if isinstance(node,ast.Name): return node.id
    if isinstance(node,ast.Attribute):
        base=_name_of(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None

def _names(node:ast.AST)->List[str]:
    out=set()
    for n in ast.walk(node):
        name=_name_of(n)
        if name: out.add(name)
    return sorted(out)

def _callee(node:ast.Call)->str:
    return _name_of(node.func) or ""

def _contains_any(name:str,toks:Sequence[str])->bool:
    c=_compact(name)
    return any(_compact(t) in c for t in toks)

def _branch_flags(stmts:Sequence[ast.stmt])->Dict[str,Any]:
    calls=[]; mutation=False; errish=False; has_return=False
    for stmt in stmts:
        for n in ast.walk(stmt):
            if isinstance(n,ast.Call):
                callee=_callee(n)
                if callee:
                    calls.append(callee)
                    mutation = mutation or _contains_any(callee,MUTATION_TOKENS)
                    errish = errish or _contains_any(callee,ERROR_TOKENS)
            elif isinstance(n,ast.Raise):
                has_return=True; errish=True
            elif isinstance(n,ast.Return):
                has_return=True
                if n.value is not None:
                    errish = errish or any(_contains_any(x,ERROR_TOKENS) for x in _names(n.value))
    return {"calls":sorted(calls),"mutation":mutation,"errorish":errish,"return":has_return}

class PyFactVisitor(ast.NodeVisitor):
    def __init__(self)->None:
        self.scope="<module>"
        self.facts:List[Dict[str,Any]]=[]
    def emit(self,node:ast.AST,kind:str,**kw:Any)->None:
        self.facts.append({"type":kind,"scope":self.scope,"line":getattr(node,"lineno",0),**kw})
    def visit_FunctionDef(self,node:ast.FunctionDef)->Any:
        old=self.scope
        self.scope=node.name
        self.emit(node,"FUNCTION_DEF",name=node.name,params=[a.arg for a in node.args.args])
        self.generic_visit(node)
        self.scope=old
    visit_AsyncFunctionDef=visit_FunctionDef
    def visit_Name(self,node:ast.Name)->Any:
        if is_versionish(node.id): self.emit(node,"VERSION_LIKE_COORDINATE",names=[node.id])
    def visit_Attribute(self,node:ast.Attribute)->Any:
        name=_name_of(node)
        if name and is_versionish(name): self.emit(node,"VERSION_LIKE_COORDINATE",names=[name])
        self.generic_visit(node)
    def _assignment(self,node:ast.AST,targets:Sequence[ast.AST],value:ast.AST|None)->None:
        if value is None:return
        rhs=_names(value)
        for t in targets:
            lhs=_names(t)
            if lhs and rhs:self.emit(node,"ASSIGNMENT_FLOW",from_names=rhs,to_names=lhs)
            if lhs and isinstance(value,(ast.Constant,ast.List,ast.Tuple,ast.Dict,ast.Set)):
                self.emit(node,"OVERWRITE_LITERAL",names=lhs)
    def visit_Assign(self,node:ast.Assign)->Any:
        self._assignment(node,node.targets,node.value); self.generic_visit(node)
    def visit_AnnAssign(self,node:ast.AnnAssign)->Any:
        self._assignment(node,[node.target],node.value); self.generic_visit(node)
    def visit_Compare(self,node:ast.Compare)->Any:
        names=_names(node)
        if names:self.emit(node,"COMPARISON_GUARD",names=names,operator=type(node.ops[0]).__name__ if node.ops else "Compare")
        self.generic_visit(node)
    def visit_Call(self,node:ast.Call)->Any:
        callee=_callee(node)
        if callee:
            arg_names=[_names(a) for a in node.args]
            names=sorted({x for group in arg_names for x in group})
            self.emit(node,"CALL_EDGE",callee=callee,names=names,arg_names=arg_names)
            if _contains_any(callee,MUTATION_TOKENS):
                self.emit(node,"MUTATION_OR_EFFECT_CALL",callee=callee,names=names)
        self.generic_visit(node)
    def visit_If(self,node:ast.If)->Any:
        th=_branch_flags(node.body); el=_branch_flags(node.orelse)
        self.emit(node,"BRANCH_CONTEXT",condition_names=_names(node.test),
                  then_calls=th["calls"],then_mutation=th["mutation"],then_errorish=th["errorish"],then_return=th["return"],
                  else_calls=el["calls"],else_mutation=el["mutation"],else_errorish=el["errorish"],else_return=el["return"])
        self.generic_visit(node)

def python_facts(source:str)->Dict[str,Any]:
    tree=ast.parse(source)
    v=PyFactVisitor(); v.visit(tree)
    return {"facts":v.facts,"parse_error":None}

def _fact_id(path:str,fact:Dict[str,Any],extractor_id:str)->str:
    return hashlib.sha256(canonical_bytes({"path":path,"extractor_id":extractor_id,"fact":fact})).hexdigest()[:24]

def _decorate(path:str,facts:Sequence[Dict[str,Any]],extractor_id:str)->List[Dict[str,Any]]:
    out=[]
    for f in facts:
        row={**f,"evidence_path":path,"extractor_id":extractor_id}
        row["deterministic_fact_id"]=_fact_id(path,f,extractor_id)
        out.append(row)
    out.sort(key=lambda x:(x.get("scope",""),x.get("line") or 0,x["type"],x["deterministic_fact_id"]))
    return out

def go_facts(files:Sequence[Dict[str,Any]],helper_path:Path|None=None)->Dict[str,Dict[str,Any]]:
    if not files:return {}
    if helper_path is None:helper_path=Path(__file__).resolve().parents[1]/"tools"/"risu_e1_go_extract.go"
    payload={"files":[{"path":r["path"],"source_b64":base64.b64encode(r["bytes"]).decode()} for r in files]}
    proc=subprocess.run(["go","run",str(helper_path)],input=canonical_bytes(payload),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    if proc.returncode!=0:
        err=proc.stderr.decode(errors="replace")[:4000]
        return {r["path"]:{"facts":[],"parse_error":f"GO_HELPER_FAILURE:{err}"} for r in files}
    data=json.loads(proc.stdout.decode())
    return {x["path"]:{"facts":x.get("facts",[]),"parse_error":x.get("parse_error")} for x in data.get("files",[])}

def extract_packet_facts(evidence:Sequence[Dict[str,Any]],go_helper_path:Path|None=None)->Dict[str,Any]:
    per=[]; allfacts=[]
    go_rows=[r for r in evidence if (r.get("language") or "").lower()=="go" and r["kind"] in {"SOURCE_TEXT","TARGET_TEXT"}]
    gomap=go_facts(go_rows,go_helper_path)
    for row in sorted(evidence,key=lambda x:x["path"]):
        if row["kind"] not in {"SOURCE_TEXT","TARGET_TEXT"}:continue
        lang=(row.get("language") or "").lower()
        if lang in {"py","python"}:
            try:parsed=python_facts(row["bytes"].decode())
            except Exception as exc:parsed={"facts":[],"parse_error":f"{type(exc).__name__}:{exc}"}
            extractor="e1.python.ast.scope.v1"
        elif lang=="go":
            parsed=gomap.get(row["path"],{"facts":[],"parse_error":"GO_RESULT_MISSING"})
            extractor="e1.go.stdlib-ast.scope.v1"
        else:
            parsed={"facts":[],"parse_error":None}; extractor="e1.generic.non_authoritative.v1"
        facts=_decorate(row["path"],parsed["facts"],extractor)
        allfacts.extend(facts)
        per.append({"path":row["path"],"sha256":row["sha256"],"language":lang,"facts":facts,"parse_error":parsed["parse_error"]})
    allfacts.sort(key=lambda x:(x["evidence_path"],x.get("scope",""),x.get("line") or 0,x["type"],x["deterministic_fact_id"]))
    return {"files":per,"facts":allfacts,"semantic_authority":False}
