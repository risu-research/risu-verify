#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
def cb(v):return (json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
def extract(provider,d):
 if provider=="openai":
  texts=[]
  for item in d.get("output",[]) or []:
   for c in item.get("content",[]) or []:
    if c.get("type")=="output_text" and isinstance(c.get("text"),str):texts.append(c["text"])
  if len(texts)!=1:raise ValueError("OPENAI_TEXT_COUNT")
  return texts[0]
 texts=[x.get("text") for x in d.get("content",[]) or [] if x.get("type")=="text" and isinstance(x.get("text"),str)]
 if len(texts)!=1:raise ValueError("ANTHROPIC_TEXT_COUNT")
 return texts[0]
def valid(x):
 if not isinstance(x,dict) or set(x)!={"outcome","confidence","evidence_paths","reason"}:return False
 if x["outcome"] not in {"DEFINITIVE_PRESERVATION","DEFINITIVE_REGRESSION","INCOMPLETE"}:return False
 if not isinstance(x["confidence"],(int,float)) or not 0<=x["confidence"]<=1:return False
 if not isinstance(x["evidence_paths"],list) or not all(isinstance(y,str) for y in x["evidence_paths"]):return False
 if not isinstance(x["reason"],str) or len(x["reason"])>2000:return False
 return True
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--provider",choices=["openai","anthropic"],required=True);ap.add_argument("--response",required=True);ap.add_argument("--output",required=True);a=ap.parse_args()
 bid="B3A_GPT56_SOL_FRONTIER" if a.provider=="openai" else "B3B_CLAUDE_OPUS45_DATED"
 try:
  d=json.loads(Path(a.response).read_bytes());x=json.loads(extract(a.provider,d))
  if not valid(x):raise ValueError("SCHEMA")
  native=x["outcome"];norm=x["outcome"];detail=x
 except Exception as e:
  native="PROVIDER_OR_SCHEMA_ERROR";norm="BASELINE_INVALID";detail={"error_type":type(e).__name__}
 out={"schema":"risu.e2-gate2d-baseline-output/v0.1","baseline_id":bid,"native_outcome":native,"normalized_outcome":norm,"details":detail}
 Path(a.output).write_bytes(cb(out))
if __name__=="__main__":main()
