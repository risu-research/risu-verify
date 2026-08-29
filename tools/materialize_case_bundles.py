#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, shutil, sys, zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
IDX=ROOT/'case-bundles'/'INDEX.json'

def sha256(p: Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
    return h.hexdigest()

def safe_extract(zf: zipfile.ZipFile, dest: Path):
    base=dest.resolve()
    for m in zf.infolist():
        target=(dest/m.filename).resolve()
        try: target.relative_to(base)
        except ValueError: raise SystemExit(f'unsafe bundle path: {m.filename}')
    zf.extractall(dest)

def main():
    idx=json.loads(IDX.read_text(encoding='utf-8'))
    cases=ROOT/'cases'; cases.mkdir(exist_ok=True)
    for b in idx['bundles']:
        p=ROOT/b['file']
        got=sha256(p)
        if got!=b['sha256']:
            raise SystemExit(f"bundle hash mismatch: {b['id']} expected={b['sha256']} actual={got}")
        target=ROOT/b['materializes_to']
        if target.exists(): shutil.rmtree(target)
        with zipfile.ZipFile(p,'r') as z: safe_extract(z,ROOT)
        actual=sum(1 for x in target.rglob('*') if x.is_file())
        if actual!=b['file_count']:
            raise SystemExit(f"materialized file-count mismatch: {b['id']} expected={b['file_count']} actual={actual}")
        print(f"PASS {b['id']} sha256={got} files={actual}")
    print('CASE BUNDLE MATERIALIZATION: PASS')
if __name__=='__main__': main()
