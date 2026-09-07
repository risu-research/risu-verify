from __future__ import annotations

"""Fail-closed, content-addressed scientific read-set guard.

The manifest is bootstrap input and must itself be bound by an out-of-band
expected SHA-256.  After bootstrap, all repository-root reads are intercepted
through Python's audit hook; an unlisted read aborts the execution.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

POLICY_SCHEMA="risu.e2-closed-runtime-read-policy/v0.1"
RECEIPT_SCHEMA="risu.e2-closed-runtime-read-receipt/v0.1"
FORBIDDEN_METADATA_KEYS={"expected_truth","gold","expected_e2_prediction","operator","operator_id","operator_name","operator_class","repair","mutation_class","verdict"}


def canonical_bytes(value: Any)->bytes:
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()

def sha256_bytes(raw: bytes)->str: return hashlib.sha256(raw).hexdigest()

def sha256_json(value: Any)->str: return sha256_bytes(canonical_bytes(value))

@dataclass(frozen=True)
class Entry:
    path:str; sha256:str; purpose:str; role:str

class ClosedReadSet:
    def __init__(self, root: Path, policy: Mapping[str,Any]):
        if policy.get("schema")!=POLICY_SCHEMA or policy.get("closed") is not True: raise ValueError("read policy not closed")
        self.root=root.resolve(strict=True); self.entries={}; self.reads=[]; self.forbidden=[]; self._guard_installed=False
        for raw in policy.get("entries",[]) or []:
            if set(raw) & FORBIDDEN_METADATA_KEYS: raise ValueError("forbidden semantic metadata in read policy")
            p=str(raw.get("path", ""));
            if not p or p in self.entries: raise ValueError("duplicate/empty read path")
            target=(self.root/p).resolve(strict=True)
            if self.root not in target.parents and target!=self.root: raise ValueError("read path escapes root")
            if (self.root/p).is_symlink(): raise ValueError("symlink scientific input forbidden")
            digest=sha256_bytes(target.read_bytes())
            if digest!=raw.get("sha256"): raise ValueError(f"preflight hash mismatch:{p}")
            self.entries[p]=Entry(p,str(raw["sha256"]),str(raw.get("purpose","")),str(raw.get("role","")))
        self.policy_digest=sha256_json(policy)

    def _rel(self, value: Any)->str|None:
        try: p=Path(os.fspath(value)).resolve(strict=False)
        except (TypeError,ValueError,OSError): return None
        if self.root==p: return "."
        if self.root in p.parents: return p.relative_to(self.root).as_posix()
        return None

    def install_audit_guard(self)->None:
        if self._guard_installed: return
        allowed=set(self.entries); root=self.root; forbidden=self.forbidden
        def hook(event:str,args:tuple[Any,...])->None:
            if event!="open" or not args: return
            rel=self._rel(args[0])
            if rel is None or rel==".": return
            # Writes are not scientific reads and are permitted only outside the
            # input allowlist; a production driver should write to a separate output dir.
            mode=str(args[1]) if len(args)>1 else "r"
            reading=not any(x in mode for x in ("w","a","x")) or "+" in mode
            if reading and rel not in allowed:
                forbidden.append(rel)
                raise PermissionError(f"closed read-set violation:{rel}")
        sys.addaudithook(hook); self._guard_installed=True

    def read_bytes(self,path:str,*,purpose:str|None=None)->bytes:
        if path not in self.entries:
            self.forbidden.append(path); raise PermissionError(f"unlisted scientific read:{path}")
        entry=self.entries[path]
        if purpose is not None and purpose!=entry.purpose: raise PermissionError(f"purpose mismatch:{path}")
        raw=(self.root/path).read_bytes(); observed=sha256_bytes(raw)
        if observed!=entry.sha256: raise PermissionError(f"runtime hash mismatch:{path}")
        self.reads.append({"path":path,"sha256":observed,"purpose":entry.purpose,"role":entry.role})
        return raw

    def receipt(self, *, source_paths:list[str]|None=None)->dict[str,Any]:
        unique={x["path"]:x for x in self.reads}
        out={"schema":RECEIPT_SCHEMA,"closed":True,"policy_digest_sha256":self.policy_digest,"reads":[unique[k] for k in sorted(unique)],
             "read_paths":sorted(source_paths if source_paths is not None else unique),"forbidden_reads":sorted(set(self.forbidden))}
        out["receipt_digest_sha256"]=sha256_json(out); return out


def load_bootstrap_policy(path:Path, expected_sha256:str)->tuple[dict[str,Any],bytes]:
    raw=path.read_bytes()
    if sha256_bytes(raw)!=expected_sha256: raise ValueError("bootstrap policy digest mismatch")
    return json.loads(raw),raw
