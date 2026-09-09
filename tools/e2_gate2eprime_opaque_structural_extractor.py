#!/usr/bin/env python3
from __future__ import annotations
import argparse, ast, hashlib, json, re, tempfile
from pathlib import Path

SCHEMA="risu.e2-gate2eprime-opaque-structural-extractor/v0.1"
SEED="RISU_GATE2EPRIME_FRESHEPISTEMIC10_R1_V1"
EXTS={".py",".js",".jsx",".ts",".tsx",".mjs",".cjs",".go",".rs"}
SKIP_DIRS={".git","node_modules","vendor",".venv","venv","dist","build","target","__pycache__"}
MAX_FILE_BYTES=2000000
AFFINITY={"py":[r"(?m)^\s*(?:from|import)\s+(?:mcp|fastmcp)(?:[\s.]|$)"],"js":[r"@modelcontextprotocol/sdk",r"['\"]fastmcp['\"]",r"['\"]mcp-framework['\"]"],"go":[r"mcp-go",r"modelcontextprotocol"],"rs":[r"(?m)^\s*(?:use|extern\s+crate)\s+(?:rmcp|mcp)"]}
JS_CALLS=("tool","registerTool","addTool","resource","registerResource","addResource","prompt","registerPrompt","addPrompt")
GO_CALLS=("AddTool","RegisterTool","AddResource","RegisterResource","AddPrompt","RegisterPrompt")
RS_MARKERS=(r"#\s*\[\s*tool(?:\s*\(|\s*\])",r"#\s*\[\s*resource(?:\s*\(|\s*\])",r"#\s*\[\s*prompt(?:\s*\(|\s*\])")

def canonical(x): return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def sha(b): return hashlib.sha256(b).hexdigest()
def locator(repo,head,path,kind,line,col,form): return "u_"+sha("\0".join([repo,head,path,kind,str(line),str(col),form]).encode())
def rank(repo,head,loc): return sha((SEED+"\0"+repo+"\0"+head+"\0"+loc).encode())
def files(root):
    out=[]
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXTS: continue
        if any(x in SKIP_DIRS for x in p.relative_to(root).parts): continue
        if p.stat().st_size<=MAX_FILE_BYTES: out.append(p)
    return sorted(out,key=lambda p:p.relative_to(root).as_posix())
def affinity(text,lang): return any(re.search(p,text) for p in AFFINITY[lang])
def py_hits(text):
    try: tree=ast.parse(text)
    except SyntaxError: return []
    out=[]; decorated=set(); reg={"tool","resource","prompt","register_tool","add_tool","register_resource","add_resource","register_prompt","add_prompt"}
    def n(x):
        if isinstance(x,ast.Call): x=x.func
        if isinstance(x,ast.Attribute): return x.attr
        if isinstance(x,ast.Name): return x.id
    for node in ast.walk(tree):
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            for d in node.decorator_list:
                k=n(d)
                if k in {"tool","resource","prompt"}:
                    out.append((k,d.lineno,d.col_offset,"decorator"))
                    if isinstance(d,ast.Call): decorated.add(id(d))
    for node in ast.walk(tree):
        if isinstance(node,ast.Call) and id(node) not in decorated:
            k=n(node)
            if k in reg: out.append((k,node.lineno,node.col_offset,"registration_call"))
    return sorted(set(out),key=lambda z:(z[1],z[2],z[0],z[3]))
def regex_hits(text,names):
    out=[]
    for name in names:
        for m in re.finditer(r"(?:\.|\b)"+re.escape(name)+r"\s*\(",text):
            line=text.count("\n",0,m.start())+1; prev=text.rfind("\n",0,m.start())
            out.append((name,line,m.start()-(prev+1),"registration_call"))
    return sorted(set(out),key=lambda z:(z[1],z[2],z[0],z[3]))
def rs_hits(text):
    out=[]
    for pat in RS_MARKERS:
        for m in re.finditer(pat,text):
            s=m.group(0); kind="tool" if "tool" in s else "resource" if "resource" in s else "prompt"
            line=text.count("\n",0,m.start())+1; prev=text.rfind("\n",0,m.start())
            out.append((kind,line,m.start()-(prev+1),"attribute"))
    return sorted(set(out),key=lambda z:(z[1],z[2],z[0],z[3]))
def discover(root,repo,head):
    units=[]
    for p in files(root):
        b=p.read_bytes()
        try: text=b.decode("utf-8")
        except UnicodeDecodeError: continue
        e=p.suffix.lower(); lang="py" if e==".py" else "js" if e in {".js",".jsx",".ts",".tsx",".mjs",".cjs"} else "go" if e==".go" else "rs"
        if not affinity(text,lang): continue
        hits=py_hits(text) if lang=="py" else regex_hits(text,JS_CALLS) if lang=="js" else regex_hits(text,GO_CALLS) if lang=="go" else rs_hits(text)
        rel=p.relative_to(root).as_posix(); fsha=sha(b)
        for kind,line,col,form in hits:
            loc=locator(repo,head,rel,kind,line,col,form)
            units.append({"opaque_unit_locator":loc,"repository_full_name":repo,"immutable_head_sha":head,"private_relative_path":rel,"private_kind":kind,"private_line":line,"private_col":col,"private_form":form,"content_sha256":fsha,"byte_count":len(b),"path_or_structural_locator_hash":sha((rel+"\0"+kind+"\0"+str(line)+"\0"+str(col)+"\0"+form).encode()),"unit_rank_sha256":rank(repo,head,loc)})
    return sorted(units,key=lambda u:(u["unit_rank_sha256"],u["opaque_unit_locator"]))
def selftest():
    with tempfile.TemporaryDirectory() as d:
        r=Path(d); (r/"a.py").write_text("from mcp.server.fastmcp import FastMCP\nmcp=FastMCP('x')\n@mcp.tool()\ndef a(): pass\n@mcp.resource('r://x')\ndef b(): pass\n"); (r/"b.ts").write_text("import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';\nserver.registerTool('c',{},async()=>({}));\n"); (r/"noise.py").write_text("@x.tool()\ndef z(): pass\n")
        u=discover(r,"owner/repo","a"*40)
        if len(u)!=3 or any(x["private_relative_path"]=="noise.py" for x in u): raise RuntimeError("SELFTEST")
        print(json.dumps({"schema":SCHEMA+"/selftest","status":"PASS","count":3},sort_keys=True,separators=(",",":")))
def main():
    p=argparse.ArgumentParser(); p.add_argument("--self-test",action="store_true"); p.add_argument("--repo-root"); p.add_argument("--repository"); p.add_argument("--head-sha"); p.add_argument("--out"); a=p.parse_args()
    if a.self_test: selftest(); return
    if not all((a.repo_root,a.repository,a.head_sha,a.out)): raise SystemExit("missing args")
    Path(a.out).write_bytes(canonical({"schema":SCHEMA,"seed":SEED,"units":discover(Path(a.repo_root),a.repository,a.head_sha)}))
if __name__=="__main__": main()
