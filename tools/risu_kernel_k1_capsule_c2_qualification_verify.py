#!/usr/bin/env python3
"""Fail-closed composite qualification replay for K1 Capsule Closure C2."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path


def run(cmd, *, capture=False):
    p=subprocess.run(cmd,text=True,capture_output=capture,check=True)
    return p.stdout if capture else ""

def git(*args): return run(["git",*args],capture=True).strip()
def load(path): return json.loads(Path(path).read_text())

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--manifest",required=True);ap.add_argument("--output",required=True);args=ap.parse_args();m=load(args.manifest)
    base=m["frozen_base"]["commit"];anchor=m["science_anchor"]["commit"];science=m["science_files"];tooling=m["qualification_tooling_files"];expected=set(science+tooling);pins=m.get("qualification_tooling_blobs",{});bootstrap=not bool(pins);checks={}

    run(["git","merge-base","--is-ancestor",base,anchor]);checks["base_is_ancestor_of_science_anchor"]=True
    run(["git","merge-base","--is-ancestor",anchor,"HEAD"]);checks["science_anchor_is_ancestor_of_head"]=True
    for path in science: run(["git","diff","--quiet",anchor,"HEAD","--",path])
    checks["science_files_byte_identical_to_anchor"]=True

    delta=git("diff","--name-status",base,"HEAD").splitlines();seen=set();all_add=True
    for line in delta:
        if not line: continue
        parts=line.split("\t");status=parts[0];path=parts[-1];seen.add(path);all_add=all_add and status=="A"
    checks["base_to_head_add_only"]=all_add
    checks["base_to_head_exact_file_set"]=seen==expected
    if not checks["base_to_head_add_only"] or not checks["base_to_head_exact_file_set"]:
        raise SystemExit(f"unexpected delta: add_only={all_add} missing={sorted(expected-seen)} extra={sorted(seen-expected)}")

    expected_pin_paths={"tools/risu_kernel_k1_capsule_c2_qualification_verify.py",".github/workflows/k1-closure-c2-qualification.yml"}
    if bootstrap:
        checks["qualification_tooling_pins"]=True
    else:
        if set(pins)!=expected_pin_paths: raise SystemExit("qualification tooling pin set mismatch")
        for path,sha in pins.items():
            actual=git("hash-object",path)
            if actual!=sha: raise SystemExit(f"tooling blob mismatch {path}: {actual} != {sha}")
        checks["qualification_tooling_pins"]=True

    run(["git","diff","--check"])
    run(["python","-m","py_compile","kernel/k1_checker_w5.py","tools/risu_kernel_k1_capsule_c2_static_verify.py","tools/risu_kernel_k1_capsule_c2_generative_verify.py","tools/risu_kernel_k1_capsule_c2_kat_verify.py",__file__])
    if git("diff","--", "kernel/k1_checker_w6.go") is None: pass
    gofmt=run(["gofmt","-d","kernel/k1_checker_w6.go"],capture=True)
    if gofmt: raise SystemExit("W6 is not gofmt canonical")
    run(["go","vet","kernel/k1_checker_w6.go"])
    with tempfile.TemporaryDirectory() as td:
        w6=str(Path(td)/"k1-checker-w6")
        run(["go","build","-trimpath","-o",w6,"kernel/k1_checker_w6.go"])
        w5=Path("kernel/k1_checker_w5.py").read_text();w6src=Path("kernel/k1_checker_w6.go").read_text()
        if "risu_kernel_k1_closure_capsule_c1_falsification" in w5 or "subprocess" in w5: raise SystemExit("W5 independence violation")
        for banned in ["os/exec","exec.Command","k1_checker_w5","k1_checker_w1","k1_checker_w2","subprocess"]:
            if banned in w6src: raise SystemExit("W6 independence violation: "+banned)
        block=re.search(r'import \((.*?)\)',w6src,re.S).group(1);imports=set(re.findall(r'"([^"]+)"',block));allowed={'bytes','crypto/sha256','encoding/hex','encoding/json','flag','fmt','os','regexp','sort','strconv','strings'}
        if imports!=allowed: raise SystemExit(f"W6 imports differ: {imports}")
        checks["source_hygiene_build_independence"]=True

        kat=Path(td)/"kat.json";static=Path(td)/"static.json";gen=Path(td)/"gen.json"
        run(["python","tools/risu_kernel_k1_capsule_c2_kat_verify.py","--w6",w6,"--output",str(kat)])
        run(["python","tools/risu_kernel_k1_capsule_c2_static_verify.py","--w6",w6,"--output",str(static)])
        run(["python","tools/risu_kernel_k1_capsule_c2_generative_verify.py","--w6",w6,"--output",str(gen)])
        k,s,g=load(kat),load(static),load(gen)

    rr=m["required_results"]
    checks["kat_pass"]=k["status"]==rr["kat"] and all(k["checks"].values())
    checks["static_pass"]=s["status"]=="PASS" and s["vector_count"]==rr["static_vectors"] and s["passed"]==rr["static_passed"] and s["failed"]==[]
    checks["generative_pass"]=g["status"]=="PASS" and g["seed"]==rr["generative_seed"] and g["trials"]==rr["generative_trials"] and g["properties_per_trial"]==rr["generative_properties_per_trial"] and g["comparisons"]==rr["generative_comparisons"] and g["passed"]==rr["generative_passed"] and g["failed"]==[]
    checks["semantic_kernel_unchanged"]=m["authority"]["semantic_kernel_changed"] is False and s["semantic_kernel_changed"] is False and g["semantic_kernel_changed"] is False
    checks["scope_is_exact_bounded_capsule"]=m["authority"]["implementation_binding"] is True and m["authority"]["arbitrary_native_program_binding"] is False and m["authority"]["implementation_scope"]=="EXACT_CAPSULE_PROGRAM_AND_FINITE_BOUNDARY"
    status="PASS" if all(checks.values()) else "FAIL"
    out={"qualification":m["qualification_id"],"status":status,"bootstrap_tooling_mode":bootstrap,"head":git("rev-parse","HEAD"),"science_anchor":anchor,"checks":checks,"kat":{"status":k["status"]},"static":{"passed":s["passed"],"vector_count":s["vector_count"],"failed":s["failed"]},"generative":{"seed":g["seed"],"passed":g["passed"],"comparisons":g["comparisons"],"failed":g["failed"]}}
    Path(args.output).write_text(json.dumps(out,sort_keys=True,indent=2)+"\n");print(json.dumps(out,sort_keys=True));return 0 if status=="PASS" else 1

if __name__=="__main__": raise SystemExit(main())
