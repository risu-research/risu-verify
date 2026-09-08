#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def collect(root:Path,manifest):
 paths=sorted(map(str,manifest.get("llm_visible_paths",[]) or []));docs=[];total=0
 forbidden=set(map(str,manifest.get("truth_or_operator_paths",[]) or []))
 if forbidden.intersection(paths):raise ValueError("TRUTH_PATH_VISIBLE")
 for p in paths:
  b=(root/p).read_bytes()
  try:s=b.decode("utf-8")
  except UnicodeDecodeError:raise ValueError("NON_UTF8_LLM_INPUT:"+p)
  total+=len(b);docs.append({"path":p,"content":s})
 if total>1048576:raise ValueError("LLM_INPUT_OVER_1MIB")
 return docs,total
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--provider",choices=["openai","anthropic"],required=True);ap.add_argument("--root",required=True);ap.add_argument("--manifest",required=True);ap.add_argument("--prompt",required=True);ap.add_argument("--schema",required=True);ap.add_argument("--config",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
 m=json.loads(Path(a.manifest).read_bytes());cfg=json.loads(Path(a.config).read_bytes());schema=json.loads(Path(a.schema).read_bytes());docs,total=collect(Path(a.root),m);prompt=Path(a.prompt).read_text();pc=cfg["providers"][a.provider]
 user="BLINDED_DOCUMENTS_JSON:\\n"+json.dumps(docs,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\\nClassify only from these blinded bytes. Return only the required JSON."
 if a.provider=="openai":
  body={"model":pc["model"],"reasoning":pc["reasoning"],"store":False,"max_output_tokens":pc["max_output_tokens"],"tools":[],
        "input":[{"role":"system","content":[{"type":"input_text","text":prompt}]},{"role":"user","content":[{"type":"input_text","text":user}]}],
        "text":{"format":{"type":"json_schema","name":"risu_gate2d_llm_baseline","strict":True,"schema":schema}}}
  headers={"Content-Type":"application/json","Authorization":"Bearer ${OPENAI_API_KEY}"}
 else:
  body={"model":pc["model"],"max_tokens":pc["max_tokens"],"thinking":pc["thinking"],"system":prompt,"messages":[{"role":"user","content":user}]}
  headers={"Content-Type":"application/json","x-api-key":"${ANTHROPIC_API_KEY}","anthropic-version":pc["anthropic_version"]}
 out={"schema":"risu.e2-gate2d-llm-request/v0.1","provider":a.provider,"lane_id":pc["lane_id"],"endpoint":pc["endpoint"],"headers_template":headers,"body":body,"visible_input_bytes":total}
 Path(a.output).write_bytes(cb(out))
if __name__=="__main__":main()
